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
   :allowed? (fn [{{:keys []} :request}]
               true)
   :handle-ok (fn [req]
                (json/write-str []))))

(defrecord AccountComponent [options]
  component/Lifecycle
  (start [component]
    component)
  (stop  [component]
    component))

(defn account-component [options]
  (map->AccountComponent options))
