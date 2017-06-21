# clj-oauth-server

## Run

```
lein run
```

## Authorize

```
# Get authorization code.
curl -XPOST "http://localhost:3000/authorize?response_type=code&client_id=6P1kUE5eEY&state=xyz&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcb&username=223&password=223" -verbose
> HTTP/1.1 302 Found
> Location: http://localhost:3001/cb?code=5KNk0V49KL?state=xyz

# Get access token.
curl -XPOST "http://localhost:3000/token?grant_type=authorization_code&client_id=6P1kUE5eEY&code=5KNk0V49KL&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcb"
> {"access_token":"o45EwnHKJQizdEvz5dWKGa","token_type":"bearer","expires_in":180000,"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"}

# Get resources.
curl -H "Authorization: Bearer o45EwnHKJQizdEvz5dWKGa" localhost:3000/api/accounts
> [{"id":0,"name":"test-user1"},{"id":1,"name":"test-user2"},{"id":2,"name":"test-user3"},{"id":3,"name":"test-user4"},{"id":4,"name":"test-user5"},{"id":5,"name":"test-user6"}]

# Introspect.
curl -XPOST "http://localhost:3000/introspect?token=o45EwnHKJQizdEvz5dWKGa"
> {"active": true, "scope": "DEFAULT", "client_id": "6P1kUE5eEY", "token_type": "bearer"}

# Refresh token.
curl -XPOST "http://localhost:3000/token?grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA"
> {"access_token":"3edoz9YwtVSnRAm4URA5Nk","token_type":"bearer","expires_in":180000,"refresh_token":"WoxgO15OGCGuqq6iGnLaFe"}

```
