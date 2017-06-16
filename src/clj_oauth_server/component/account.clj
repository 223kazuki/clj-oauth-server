(ns clj-oauth-server.component.account
  (:require [com.stuartsierra.component :as component]
            [clojure.tools.logging :as log]
            [clojure.java.io :as io]
            [liberator.core :as liberator]
            [clj-oauth-server.component.datomic :as d]
            [clj-oauth-server.component.authorization :as auth]
            [clojure.data.json :as json])
   (:import [java.util UUID]))

(defn list-resource
  [{:keys [datomic auth] :as account}]
  (liberator/resource
   :available-media-types ["application/json"]
   :allowed-methods [:get :post]
   :allowed? (fn [context]
               (let [{:keys [headers] :as request} (:request context)
                     access_token (-> headers
                                      (get "authorization")
                                      (clojure.string/split #" ")
                                      second)
                     auth-info (auth/get-auth auth access_token)]
                 auth-info))
   :handle-ok (fn [req]
                (json/write-str [{:id 0
                                  :name "test-user1"}
                                 {:id 1
                                  :name "test-user2"}
                                 {:id 2
                                  :name "test-user3"}
                                 {:id 3
                                  :name "test-user4"}
                                 {:id 4
                                  :name "test-user5"}
                                 {:id 5
                                  :name "test-user6"}]))))

(defrecord AccountComponent [options]
  component/Lifecycle
  (start [component]
    component)
  (stop  [component]
    component))

(defn account-component [options]
  (map->AccountComponent options))
