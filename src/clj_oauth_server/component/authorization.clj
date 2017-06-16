(ns clj-oauth-server.component.authorization
  "Provides a access token."
  (:require [com.stuartsierra.component :as component]
            [clojure.tools.logging :as log]
            [clojure.java.io :as io]
            [clojure.core.cache :as cache]
            [liberator.core :as liberator]
            [clj-oauth-server.component.datomic :as d]
            [re-rand :refer [re-rand]]
            [clojure.data.json :as json]
            [hiccup.page :refer [html5 include-css include-js]])
  (:import [java.util UUID]))

(def db
  {:client [{:client_id        "6P1kUE5eEY"
             :client_secret    "lxcK6KWOTN"
             :client_type      "PUBLIC"
             :redirect_uris    "http://localhost:3001/cb"
             :application_name "Sample Application"
             :application_type "WEB"}]
   :user   [{:id       "223"
             :password "223"}]})

(defn login-page [auth context]
  (html5
   [:head
    [:meta {:charset "utf-8"}]
    [:meta {:name "viewport" :content "width=device-width, initial-scale=1"}]
    (include-css "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.0/css/bootstrap.min.css")
    (include-css "/css/main.css")
    (include-css "https://maxcdn.bootstrapcdn.com/font-awesome/4.6.1/css/font-awesome.min.css")
    (include-css "https://fonts.googleapis.com/css?family=Passion+One")
    (include-css "https://fonts.googleapis.com/css?family=Oxygen")
    [:title "Login"]]
   [:body
    [:div.container
     [:div.row.main
      [:div.panel-heading
       [:div.panel-title.text-center
        [:h1.title "OAuth 2.0 Server"]
        [:hr ]]]
      [:div.main-login.main-center
       [:form.form-horizontal {:method "post" }
        (when-let [error (:error context)]
          [:div.alert.alert-danger error])
        [:div.form-group
         [:label.cols-sm-2.control-label {:for "username"} "Your Name"]
         [:div.cols-sm-10
          [:div.input-group
           [:span.input-group-addon [:i.fa.fa-user.fa {:aria-hidden true}]]
           [:input.form-control {:type "text" :name "username" :id "name" :placeholder "Enter your Name"}]]]]
        [:div.form-group
         [:label.cols-sm-2.control-label {:for "password"} "Password"]
         [:div.cols-sm-10
          [:div.input-group
           [:span.input-group-addon [:i.fa.fa-lock.fa-lg {:aria-hidden true}]]
           [:input.form-control {:type "password" :name "password" :id "password" :placeholder "Enter your Password"}]]]]
        [:div.form-group
         [:button.btn.btn-primary.btn-lg.btn-block.login-button {:type "submit"} "Login"]]]]]]
    (include-js "https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js")
    (include-js "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.0/js/bootstrap.min.js")]))

(defn find-client-by-id [datomic client-id]
  (->> db
       :client
       (filter #(= (:client_id %) client-id))
       first))

(defn authenticate-user [datomic username password]
  (->> db
       :user
       (filter #(and (= (:id %) username)
                     (= (:password %) password)))
       first))

(defprotocol IOAuth2Provider
  (new-code  [this client])
  (new-token [this code client-id redirect-uri])
  (get-auth   [this token]))

(defn get-port-or-default-port
  [uri]
  (let [port (.getPort uri)]
    (if-not (== port -1)
      port
      (try
        (.. uri toURL getDefaultPort)
        (catch Exception e
          -1)))))

(defn get-redirect-uri
  [redirect-uri response-type client]
  (let [{:keys [client_type redirect_uris]} client
        redirect-uris (some-> redirect_uris
                              (clojure.string/split #" "))
        specified-redirect-uri (when redirect-uri (java.net.URI. redirect-uri))]
    (when-not (or (and (empty? redirect-uris)
                       (or (= client_type "PUBLIC")
                           (= response-type "token")))
                  (if (nil? redirect-uri)
                    (not= 1 (count redirect_uris))
                    (if (empty? redirect-uris)
                      (or (not (.isAbsolute specified-redirect-uri))
                          (.getFragment specified-redirect-uri))
                      (or (not (.isAbsolute specified-redirect-uri))
                          (.getFragment specified-redirect-uri)
                          (not-any? #(let [registerd (java.net.URI. %)]
                                       (or
                                        (and (.getQuery registerd)
                                             (= (.equals registerd specified-redirect-uri)))
                                        (and (= (.getScheme specified-redirect-uri) (.getScheme registerd))
                                             (= (.getUserInfo specified-redirect-uri) (.getUserInfo registerd))
                                             (.equalsIgnoreCase (.getHost specified-redirect-uri) (.getHost registerd))
                                             (== (get-port-or-default-port specified-redirect-uri)
                                                 (get-port-or-default-port registerd))
                                             (= (.getPath specified-redirect-uri) (.getPath registerd)))))
                                    redirect-uris)))))
      (let [redirect-uri (if (and (nil? redirect-uri)
                                  (= 1 (count redirect_uris)))
                           (first redirect-uri)
                           redirect-uri)]
        (condp = (:application_type client)
          "WEB"    (when-not (and (= response-type "token")
                                  (or (not= "https" (.getScheme (java.net.URI. redirect-uri)))
                                      (= "localhost" (.getHost (java.net.URI. redirect-uri)))))
                     redirect-uri)
          "NATIVE" (when-not (or (= "https" (.getScheme (java.net.URI. redirect-uri)))
                                 (and (= "http" (.getScheme (java.net.URI. redirect-uri)))
                                      (not= "localhost" (.getHost (java.net.URI. redirect-uri)))))))))))

(defn authorization-error-response
  [redirect-uri error-code state]
  {:status 302
   :headers {"Location" (format "%s?error=%s&state=%s" redirect-uri error-code state)}})

(defn authorize-resource
  [{:keys [datomic] :as auth}]
  (fn [request]
    (let [{:keys [response_type client_id redirect_uri scope state
                  username password]} (:params request)
          explicit-redirect-uri? (some? redirect_uri)
          scope (or scope "DEFAULT")
          client (find-client-by-id datomic client_id)]
      (if-let [redirect-uri (and response_type
                                 client_id
                                 client
                                 (get-redirect-uri redirect_uri response_type client))]
        (case response_type
          "code"
          (cond
            (not (authenticate-user datomic username password))
            {:status 200
             :headers {"Content-Type" "text/html"}
             :body (login-page auth {:error "Invalid username or password."})}

            :else
            (let [code (new-code auth {:client_id client_id
                                       :redirect_uri ((-> client
                                                          :redirect_uris
                                                          (clojure.string/split #" ")
                                                          set) redirect_uri)
                                       :explicit-redirect-uri? explicit-redirect-uri?
                                       :scope scope})]
              {:status 302
               :headers {"Location" (format "%s?code=%s&state=%s" redirect_uri code state)}}))

          ;; TODO
          "token"
          (authorization-error-response redirect_uri "unsupported_response_type" state)

          (authorization-error-response redirect_uri "unsupported_response_type" state))
        {:status 200
         :headers {"Content-Type" "text/html"}
         :body (login-page auth {:error "Invalid oauth 2.0 parameters."})}))))

(defn access-token-resource
  [{:keys [datomic] :as auth}]
  (fn [request]
    (let [{:keys [grant_type code redirect_uri client_id]} (:params request)]
      (case grant_type
        "authorization_code"
        (if-let [access-token (and (find-client-by-id datomic client_id)
                                   (new-token auth code client_id redirect_uri))]
          (let [{:keys [token-type expires-in refresh-token]} (get-auth auth access-token)]
            {:status 200
             :headers {"Content-Type" "application/json;charset=UTF-8" "Cache-Control" "no-store" "Pragma" "no-cache"}
             :body (json/write-str
                    {:access_token access-token
                     :token_type token-type
                     :expires_in expires-in
                     :refresh_token refresh-token})})
          {:status 400
           :headers {"Content-Type" "application/json;charset=UTF-8" "Cache-Control" "no-store" "Pragma" "no-cache"}
           :body (json/write-json {:error "invalid_grant"})})
        {:status 400
         :headers {"Content-Type" "application/json;charset=UTF-8" "Cache-Control" "no-store" "Pragma" "no-cache"}
         :body (json/write-json {:error "unsupported_grant_type"})}))))

(defn introspect-resource
  [{:keys [datomic] :as auth}]
  (liberator/resource
   :available-media-types ["application/x-www-form-urlencoded" "application/json"]
   :allowed-methods [:get]
   :handle-ok (fn [{:keys [request]}]
                (let [{:keys [token token_type_hint]} (:params request)
                      {:keys [client] :as token-info} (get-auth auth token)]
                  (json/write-str {:active     (some? token-info)
                                   :scope      "DEFAULT"
                                   :client_id  (:client-id client)
                                   :token_type "bearer"})))))

(defrecord AuthorizationComponent [disposable?]
  component/Lifecycle

  (start [component]
    (if (:token-cache component)
      component
      (assoc component
             :code-cache (atom (cache/ttl-cache-factory {} :ttl (* 10 60 1000)))
             :token-cache (atom (cache/ttl-cache-factory {} :ttl (* 30 60 1000))))))

  (stop [component]
    (if disposable?
      (dissoc component :code-cache :token-cache)
      component))

  IOAuth2Provider
  (new-code [component client]
    (let [{:keys [client_id redirect_uri]} client
          code (re-rand #"[a-zA-Z0-9]{10}")]
      (swap! (:code-cache component) assoc code {:client client :used? false})
      code))

  (new-token [component code client-id redirect-uri]
    (when-let [{:keys [client used? access-token]}
               (cache/lookup @(:code-cache component) code)]
      (when (and (= (:client_id client) client-id)
                 (= (:redirect_uri client) redirect-uri))
        (if used?
          (do
            (swap! (:token-cache component) dissoc access-token)
            (swap! (:code-cache component) dissoc code))
          (let [access-token  (re-rand #"[a-zA-Z0-9]{22}")
                refresh-token (re-rand #"[a-zA-Z0-9]{22}")]
            (swap! (:token-cache component) update-in [access-token]
                   #(assoc %
                           :client client :expires-in 1800 :token-type "bearer"
                           :refresh-token refresh-token))
            (swap! (:code-cache component) update-in [code]
                   #(assoc % :used? true :access-token access-token))
            access-token)))))

  (get-auth [component access-token]
    (cache/lookup @(:token-cache component) access-token)))

(defn authorization-component [options]
  (map->AuthorizationComponent options))
