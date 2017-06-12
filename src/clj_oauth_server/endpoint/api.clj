(ns clj-oauth-server.endpoint.api
  (:require [compojure.core :refer :all]
            [clojure.java.io :as io]
            [clj-oauth-server.component.authorization :as authorization]
            [clj-oauth-server.component.account :as account]))

(defn api-endpoint [{:keys [auth account] :as config}]
  (routes
   ;; OAuth 2.0
   (GET  "/authorize" [] (authorization/login-page auth nil))
   (POST "/authorize" [] (authorization/authorize-resource auth))
   (POST "/token" [] (authorization/access-token-resource auth))
   (GET  "/introspect" [] (authorization/introspect-resource auth))

   ;; Resource
   (GET "/api/accounts" [] (account/list-resource account))
   (GET  "/ping" [] "PONG")))
