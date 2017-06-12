# clj-oauth-server

```
curl -XPOST "http://localhost:3000/authorize?response_type=code&client_id=6P1kUE5eEY&state=xyz&redirect_uri=https%3A%2F%2Fmeidai-sumo%2Eclub%2Fcb&username=223&password=223" -verbose
> HTTP/1.1 302 Found
> Location: https://meidai-sumo.club/cb?code=5KNk0V49KL?state=xyz

curl -XPOST "http://localhost:3000/token?grant_type=authorization_code&client_id=6P1kUE5eEY&code=5KNk0V49KL&redirect_uri=https%3A%2F%2Fmeidai-sumo%2Eclub%2Fcb"
> {"access_token":"o45EwnHKJQizdEvz5dWKGa","token_type":"example","expires_in":3600,"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"}

curl -H "Authorization: Bearer o45EwnHKJQizdEvz5dWKGa" localhost:3000/api/accounts
> [{"id":0,"name":"test-user1"},{"id":1,"name":"test-user2"},{"id":2,"name":"test-user3"},{"id":3,"name":"test-user4"},{"id":4,"name":"test-user5"},{"id":5,"name":"test-user6"}]

```
