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

(defn find-client-by-id [client-id]
  (->> db
       :client
       (filter #(= (:client_id %) client-id))
       first))

(defn authenticate-user [username password]
  (->> db
       :user
       (filter #(and (= (:id %) username)
                     (= (:password %) password)))
       first))

(defprotocol IOAuth2Provider
  (new-code  [this client])
  (auth-code [this code])
  (new-token [this token-info])
  (auth-by   [this token]))

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
                              (clojure.string/split #" "))]
    (when-not (or (and (empty? redirect-uris)
                       (or (= client_type "PUBLIC")
                           (= response-type "token")))
                  (if (nil? redirect-uri)
                    (not= 1 (count redirect_uris))
                    (if (empty? redirect-uris)
                      (or (not (.isAbsolute (java.net.URI. redirect-uri)))
                          (.getFragment (java.net.URI. redirect-uri)))
                      (or (not (.isAbsolute (java.net.URI. redirect-uri)))
                          (.getFragment (java.net.URI. redirect-uri))
                          (not-any? #(let [specified (java.net.URI. redirect-uri)
                                           registerd (java.net.URI. %)]
                                       (or
                                        (and (.getQuery registerd)
                                             (= (.equals registerd specified)))
                                        (and (= (.getScheme specified) (.getScheme registerd))
                                             (= (.getUserInfo specified) (.getUserInfo registerd))
                                             (.equalsIgnoreCase (.getHost specified) (.getHost registerd))
                                             (== (get-port-or-default-port specified)
                                                 (get-port-or-default-port registerd))
                                             (= (.getPath specified) (.getPath registerd)))))
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
          client (find-client-by-id client_id)]
      (if-let [redirect-uri (and response_type
                                 client_id
                                 client
                                 (get-redirect-uri redirect_uri response_type client))]
        (case response_type
          "code"
          (cond
            (not (authenticate-user username password))
            {:status 200
             :headers {"Content-Type" "text/html"}
             :body (login-page auth {:error "Invalid username or password."})}

            :else
            (let [code (new-code auth {:client_id client_id
                                       :redirect_uri ((-> client
                                                          :redirect_uris
                                                          (clojure.string/split #" ")
                                                          set) redirect_uri)
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
        (let [client (auth-code auth code)]
          (if (and (not (nil? client))
                   (= (:redirect_uri client) redirect_uri)
                   (= (:client_id client) client_id))
            (let [access-token (new-token auth client)]
              {:status 200
               :headers {"Content-Type" "application/json;charset=UTF-8" "Cache-Control" "no-store" "Pragma" "no-cache"}
               :body (json/write-str
                       {:access_token access-token
                        :token_type "example"
                        :expires_in 3600
                        :refresh_token "tGzv3JOkF0XG5Qx2TlKWIA"})})
            {:status 401
             ;; TODO: How to respnse to invalid token request.
             }))))))

(defn introspect-resource
  [{:keys [datomic] :as auth}]
  (liberator/resource
   :available-media-types ["application/x-www-form-urlencoded" "application/json"]
   :allowed-methods [:get]
   :handle-ok (fn [{:keys [request]}]
                (let [{:keys [token token_hint]} (:params request)
                      token-info (auth-by auth token)]
                  (json/write-str {:active    (not (nil? token-info))
                                   :client_id "l238j323ds-23ij4"
                                   :username  "jdoe"
                                   :scope     (:scope token-info)
                                   :sub       "Z5O3upPC88QrAjx00dis"
                                   :aud       "https://protected.example.net/resource"
                                   :iss       "https://server.example.com/"
                                   :exp       1419356238
                                   :iat       1419350238})))))

(defrecord AuthorizationComponent [disposable?]
  component/Lifecycle

  (start [component]
    (if (:token-cache component)
      component
      (let [code-cache (atom (cache/ttl-cache-factory {} :ttl (* 10 60 1000)))
            token-cache (atom (cache/ttl-cache-factory {} :ttl (* 30 60 1000)))]
        (assoc component
               :code-cache code-cache
               :token-cache token-cache))))

  (stop [component]
    (if disposable?
      (dissoc component :code-cache :token-cache)
      component))

  IOAuth2Provider
  (new-code [component client]
    (let [{:keys [client_id redirect_uri]} client
          code (re-rand #"[a-zA-Z0-9]{10}")]
      (swap! (:code-cache component) assoc code client)
      code))
  (auth-code [component code]
    (when-let [client (cache/lookup @(:code-cache component) code)]
      (swap! (:code-cache component) dissoc code)
      client))
  (new-token [component token-info]
    (let [access-token (re-rand #"[a-zA-Z0-9]{22}")]
      (swap! (:token-cache component) assoc access-token token-info)
      access-token))

  (auth-by [component access-token]
    (cache/lookup @(:token-cache component) access-token)))

(defn authorization-component [options]
  (map->AuthorizationComponent options))
