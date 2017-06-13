(ns clj-oauth-server.component.authorization-test
  (:require [clj-oauth-server.component.authorization :as auth]
            [clj-oauth-server.component.account :as account]
            [clj-oauth-server.component.datomic :as datomic]
            [com.stuartsierra.component :as component]
            [clojure.pprint :refer :all]
            [clojure.test :refer :all]
            [clojure.data.json :as json]))

(def test-config
  {:datomic {:recreate? true
             :uri       "datomic:mem://test"}})

(defn test-system [config]
  (-> (component/system-map
       :auth    (auth/authorization-component {})
       :account (account/account-component {})
       :datomic (datomic/datomic-component (:datomic config)))
      (component/system-using
       {:auth [:datomic]
        :account [:auth :datomic]})
      (component/start-system)))

(deftest authorize-test
  (let [system               (test-system test-config)
        authorize-handler    (auth/authorize-resource (:auth system))
        access-token-handler (auth/access-token-resource (:auth system))
        introspect-handler   (auth/introspect-resource (:auth system))
        account-handler      (account/list-resource (:account system))]
    (testing "Authorize successfully."
      ;; http://localhost:3000/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
      (let [request {:request-method :post
                     :content-type   "application/x-www-form-urlencoded"
                     :params         {:response_type "code"
                                      :client_id     "6P1kUE5eEY"
                                      :state         "3lR1fhAqmF"
                                      :redirect_uri  "http://localhost:3001/cb"
                                      :username      "223"
                                      :password      "223"}}
            {:keys [status headers body] :as res}
            (authorize-handler request)

            uri                  (java.net.URI. (get headers "Location"))
            {:keys [code state]} (->> (clojure.string/split (.getQuery uri) #"&")
                                      (map #(clojure.string/split % #"="))
                                      (reduce #(assoc %1 (keyword (first %2)) (second %2)) {}))]
        (are [x y] (= x y)
          302                status
          "http"             (.getScheme uri)
          "localhost"        (.getHost uri)
          "/cb"              (.getPath uri)
          "3lR1fhAqmF"       state)
        (let [request                               {:request-method :post
                                                     :content-type   "application/x-www-form-urlencoded"
                                                     :params         {:grant_type   "authorization_code"
                                                                      :client_id    "6P1kUE5eEY"
                                                                      :redirect_uri "http://localhost:3001/cb"
                                                                      :code         code}}
              {:keys [status headers body] :as res} (access-token-handler request)
              {:keys [access_token token_type
                      expires_in refresh_token]}    (json/read-str body :key-fn keyword)]
          (are [x y] (= x y)
            200 status)
          (let [request {:request-method :get
                         :content-type   "application/x-www-form-urlencoded"
                         :params         {:token      access_token
                                          :token_hint "test"}}
                {:keys [status headers body] :as res}
                (introspect-handler request)
                {:keys [active client_id username scope sub aud iss exp iat] :as res}
                (json/read-str body :key-fn keyword)]
            (are [x y] (= x y)
              200    status
              active true))
          (let [request {:request-method :get
                         :content-type   "application/json"
                         :headers {"authorization" (str "Bearer " access_token)}}
                {:keys [status headers body] :as res}
                (account-handler request)
                accounts (json/read-str body :key-fn keyword)]
            (are [x y] (= x y)
              200    status
              [{:id 0
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
                :name "test-user6"}] accounts)))))))
