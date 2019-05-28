# Service Provider API for OP Identity Service Broker

2019-05-27

OP Identification Service Broker allows Service Providers to implement strong electronic identification (Finnish bank credentials, Mobile ID) easily to websites and mobile apps via single API.

To identify the user the Service Provider (your website) redirects the user to the Identification Service Broker (OP) with an authorization request. The user chooses the Identity Provider (a bank or Mobile ID) and is redirected there where he/she authenticates with his/her own credentials. OP will process the authentication result, and return the user to your website with verified information about the identity of the user.

### Sandbox users

OP Identity Service Provider does not require registration and uses fixed credentials (Client ID & encryption keys). __See section 13__.

Table of contents:
1. Definitions
2. Prerequisites
3. Security concerns
4. Flow with hosted Identity Service Broker UI
5. Flow with embedded Identity Service Broker UI
6. GET /api/embedded-ui/{client_id}
7. GET/POST /oauth/authorize
8. POST /oauth/token
9. Identity token
10. GET /oauth/profile
11. GET /.well-known/openid-configuration
12. JWKS
13. Public Sandbox for customer testing
14. Service Provider code example
15. Libraries for Service Provider
16. Javascript
17. PHP
18. Extra material
19. Support
20. Pricing
21. Watching changes

## 1. Definitions

- **Service Provider (SP)** is the service asking for the user identity.
- **Identity Service Broker (ISB)** is the OP service that lets the user choose an identity provider and that passes the requested user identity information to the service provider.
- **Identity Provider (IdP)** is a provider of identification, i.e. a Bank or mobile ID.
- **Identity Service Broker UI** is a list of Identity Providers shown on the UI. There are two options for displaying the UI. Service Provider can redirect the user to the hosted UI in the Identity Service Broker or embed the UI into its own UI.
- **OIDC** or OpenID Connect is a standard easy to use protocol for identifying and authenticating users.
- **JWT** or JSON Web Token is a standard for wrapping attributes into a token. JWS is a signed and JWE an encrypted JWT token.
- **JWKS** JSON Web Key Set is a standard way to exchange public keys between SP and ISB.

## 2. Prerequisites

To identify users using the Identity Service Broker and the OIDC API for Service Providers, you need the following pieces of configuration:

* Client identifier

  Your service is identified by a unique client identifier string, which OP will generate for you during the onboarding process.

* OP OIDC authorization endpoint

  The OP OIDC authorization endpoint for production use is `https://isb.op.fi/oauth/authorize`. For testing please use the sandbox endpoint `https://isb-test.op.fi/oauth/authorize`.

* OP OIDC token endpoint

  The OP OIDC token endpoint for production use is `https://isb.op.fi/oauth/token`. For testing please use the sandbox endpoint `https://isb-test.op.fi/oauth/token`.

* OP OIDC profile endpoint

  The OP OIDC profile endpoint for production use is `https://isb.op.fi/oauth/profile`. For testing please use the sandbox endpoint `https://isb-test.op.fi/oauth/profile`. This endpoint provides exactly the same information as the token endpoint and as such is redundant.

* RSA keypair to sign requests

   Signing is used for verifying that requests originate from the SP. Signing is used in requests to two endpoints: /oauth/authorize and /oauth/token.

To generate a 2048 bit RSA key run the command `openssl genrsa -out private.pem 2048` (you could replace the filename private.pem with one of your own choosing).

* RSA keypair to decrypt identity token

  OP will encrypt the identity token identifying the user with your public key and you will have to decrypt it with your private key. Keys are generated the same way as signing keys. Both encryption and signing public keys must be published in the SP's JKWS endpoint. Keep the private portions of these keypairs private.

* OP JWKS endpoint

  Identity tokens are signed by OP to protect their content. You must verify the signature against OP's public key which can be fetched from the OP JWKS endpoint `https://isb.op.fi/jwks/broker`. For testing please use the sandbox endpoint `https://isb-test.op.fi/jwks/broker`. Note that the keys are rolled over at times. The endpoint may contain several valid keys. You may safely cache keys for at most one day. When fetching keys from endpoint you must verify the TLS certificate to ensure that the keys are genuine.

## 3. Security concerns

- Private RSA keys must be protected and not revealed to users.
- The keys should be rotated every now and then. When depracating a key you should remove it from your JWKS endpoint at least one day before deactivating it to prevent disruptions to service. We may cache your public keys for up to one day on the ISB.
- Keys must not be sent to the user's browser. I.e. processing the identification should be done server side, not in browser side Javascript.

## 4. Flow with hosted Identity Service Broker UI

  OP identification service uses the OpenID Connect Authorization Code flow. I.e. the following steps are taken to identify a user:

1. Service Provider directs the user to OP's service endpoint with parameters documented below. `ftn_idp_id` shall not exist among request parameters
2. OP lets the user identify themselves using a provider of their choosing.
3. Once identified, the user is passed back to the Service Provider's `redirect_uri` with an access code.
4. The Service Provider makes a direct API call to the OP API and gets an encrypted and signed identity token in exchange for the access code.

![Flow graph](./flow.png?raw=true)

## 5. Flow with embedded Identity Service Broker UI

  OP identification service uses the OpenID Connect Authorization Code flow. I.e. the following steps are taken to identify a user:

1. Service Provider uses the /api/embedded-ui/{client_id} API to get the data to display the embedded Identity Service Broker UI on the SP UI.
2. Service Provider lets the user choose identity provider.
3. Service Provider directs the user to OP's service endpoint with parameters documented below. `ftn_idp_id` shall be delivered as request parameter
4. Once identified, the user is passed back to the Service Provider's `redirect_uri` with an access code.
5. The Service Provider makes a direct API call to the OP API and gets an encrypted and signed identity token in exchange for the access code.

![Flow graph](./embedded-ui-flow.png?raw=true)

## 6. GET /api/embedded-ui/{client_id}

To display the embedded Identity Service Broker UI the Service Provider shall use the /api/embedded-ui/{client_id} API of the Identity Service Broker to get the needed data. Client_id is the client identifier that specifies which service provider is asking for identification. Service Provider does not need to use this API if it uses the flow with hosted Identity Service Broker UI.

The query string of the request can include the following optional parameter:
- **lang** indicates the language for the returned data (`fi`, `sv` or `en`). If parameter is omitted the default language is `fi`.

Example API calls:

`GET https://isb-test.op.fi/api/embedded-ui/example_service_provider`

`GET https://isb-test.op.fi/api/embedded-ui/example_service_provider?lang=en`

The API returns json data.

Example of returned data:
```json
{
  "identityProviders": [
    {
        "name": "Osuuspankki",
        "imageUrl": "https://isb-test.op.fi/public/images/idp/op_140x75.png",
        "ftn_idp_id": "fi-op"
    },
    {
        "name": "Nordea",
        "imageUrl": "https://isb-test.op.fi/public/images/idp/nordea_140x75.png",
        "ftn_idp_id": "fi-nordea"
    }
  ],
  "isbProviderInfo": "OP Identity Service Broker is provided by OP Financial Group member cooperative banks and OP Corporate  Bank plc",
  "isbConsent": "By continuing, I accept that the service provider will receive my name and personal identity code"
}
```

Service Provider needs to use and display these two fields `isbProviderInfo` and `isbConsent` on the UI.

API errors:

| Error | Description | Action |
| --- | --- | --- |
| 404 Not found | the given client_id is not valid | error is shown on ISB |

## 7. GET/POST /oauth/authorize

To initiate the identification process the service provider directs the user to OP's OIDC endpoint either by redirect or by direct link. The request parameters are passed to the ISB in a signed JWS token. The token is sent in the GET request's query string as `request` parameter or in the POST request in `payload` as a JSON having structure `{request: <JWS_TOKEN>}`. The following parameters are supported in the authorization request as WJS token claims:

- **client_id** is the client identifier that specifies which service provider is asking for identification.
- **redirect_uri** specifies to which URI on your site (the service provider) you want the user to return to once identification is done. This URI must be registered with OP (except when using the sandbox environment) to prevent other services misusing your credentials.
- **response_type** value must be `code`.
- **scope** is a space separated list of scopes, or  basically sets of information requested. This must include `openid` and `personal_identity_code` and can optionally include also `profile`, `weak` and `strong`. Other scope values are rejected. For example `openid profile personal_identity_code` is accectable. The `profile` includes `name`, `given_name`, `family_name` and `birthdate`. If the Service Provider's purpose for identifying the user is to create new identification methods, i.e. for example to create an user account with username and password, then the Service Provider must report such purpose by adding either `weak` (for weak identifiers, for example password account) or `strong` (for strong electronic identification which is only for members of the Finnish Trust Network) to the scopes. Using weak or strong as a purpose may affect pricing and depends on your contract.

The following optional parameters may be used:
- **ui_locales** selects user interface language (`fi`, `sv` or `en`).
- **nonce** value is passed on to identity token as is.
- **prompt** can be set to `consent` to indicate that the user should be asked to consent to personal data being transferred. In this case the Identity Service Broker will display a verification screen after the user has been authenticated.
- **state** is an opaque value you can use to maintain state between request and callback. Use of `state` is recommended.
- **ftn_idp_id** shall be delivered if the SP has the embedded Identity Service Broker UI. Parameter contains the id of the user chosen idp.

The JWS token must be signed with the RS256 algorithm with SP's signing key.

Example identification request:

`GET https://isb-test.op.fi/oauth/authorize?request=eyJhb[...]`
`POST https://isb-test.op.fi/oauth/authorize with payload set as {request=eyJhb[...]}`

Once the identification process is done or if there is a recoverable error, the user is directed back to the service provider to the URI specified in the request. The following parameters are included in the query string:
- **state** is passed as is from the request.
- **code** is the authorization code for use in the next phase (only included after succesful identification).
- **error** is the reason why identification failed (in case of error only).

Example return:

`GET https://example-service-provider.example/bell?code=eyJhb[...]4bGg&state=GIlBncQk4vsbThjMNBJ49G` using Hapi / Bell library on javascript

`GET http://example-service-provider/?code=eyJh[....]_0w&state=77deb5b7f773ef6dafc12d9cf0588f57` using league/oauth2-client library on PHP

API errors:

| Error | Description | Action |
| --- | --- | --- |
| invalid_request | request parameter validation fails | redirected to the SP with error and error description|
| invalid_scope | openid or personal_identity_code scope is missing. Validation fails | redirected to the SP with error and error description|
| access_denied | user cancels or returns back to SP | redirected to the SP with error and error description|
| various validation errors | initial validation errors e.g. on invalid client_id, invalid or unsigned JWT etc.| error and error description are shown on ISB without return link back to SP |
| various errors during identification | OIDC, Saml2 or Tupas identification might go wrong for a number of reasons | error and error description are shown on ISB with return link back to SP |


## 8. POST /oauth/token

The actual user identity token from the token endpoint can be fetched using the /oauth/token API. The following parameters shall be included as request payload parameters:
- **code** authorization code, which was returned in succesful /oauth/authorize/ reply. Mandatory.
- **grant_type** needs to have value `authorization_code`. Mandatory.
- **client_assertion_type** must be `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
- **client_assertion** is a signed JWS authentication token. The JWS must be signed with the RS256 algorithm with SP's signing key.

The client_assertion is signed using the SP's signing key and must contain the following claims:
- **iss** Issuer. This must contain the client_id.
- **sub** Subject. This must contain the client_id.
- **aud** Audience. The aud (audience) Claim. ISB's token endpoint URL.
- **jti** JWT ID. A unique identifier for the token, which can be used to prevent reuse of the token. These tokens must only be used once.
- **exp** Expiration time for the token. This is seconds since UNIX epoch (UTC). Suggested time is 600 seconds in the future.

Example identification request:

`POST https://isb-test.op.fi/oauth/token`

client_assertion is a JWS token and it might look like this (captured using the PHP based demo service provider example __See section 14__):
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzYWlwcHVha2F1cHBpYXMiLCJzdWIiOiJzYWlwcHVha2F1cHBpYXMiLCJhdWQiOiJodHRwczovL2lzYi10ZXN0Lm9wLmZpL29hdXRoL2F1dGhvcml6ZSIsImp0aSI6IjExOTk5YzA3N2VkMWQ1MjJjNGJjMmIiLCJleHAiOjE1NTkwNDI2ODJ9.IZGs7llsatuOWsV3IHNnO9hFtGrmNX-VIuYvpi8GI4Bi7isuOFX_8dmBXQ8gxjnvWCdG4nBuuwTWxIg1_l8801UqOM4jouHXsUF_ZnT72hPKzZSm2hRKiCJfj-uE6FJ0Vc4KTpxlWCrRmoMBUorOUYiJViNVkk36z_WQb0Whi_ObVEUsNoLjtuHxVoHNQ4CLoj-xq3pRb2BIp78i2fbu0mUf8wGSOzSE5sM7UcFpTX49KVSIqgSr81xlpDobh0KpmZer9YPdvlCMRWVPO6MLlGmmMjgjbkOxOeJ_e9BtiAHkhDjZYwM1mFlbgHxPHU46lfcjdcCI9stCnX3_sw4c6g
```

The following is a snapshot of the payload inside the JWS token captured using the PHP based demo service provider example __See section 14__  :
```json
{
  "iss": "saippuakauppias",
  "sub": "saippuakauppias",
  "aud": "https://isb-test.op.fi/oauth/authorize",
  "jti": "11999c077ed1d522c4bc2b",
  "exp": 1559042682
}
```

The API returns json data.

Example of returned data:
```json
{
  "access_token": "eyJh[...]2A",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJl[...]Nw"
}
```

API errors:

| Error | Description |
| --- | --- |
| bad_request | invalid input parameters |
| unauthorized_client | the given client_id is not valid, assertion error etc. |
| server_error | fetching client data failed  |


The error and error description are shown on ISB with return link back to SP. In some cases however if certain library is used, an error is displayed on SP side and the error might be different than above.

Parameter explanations:
- **access_token** Access Token for the /oauth/profile API (OIDC UserInfo Endpoint)
- **token_type** OAuth 2.0 Token Type value. The value is always `Bearer`
- **expires_in** Expiration time of the Access Token in seconds since the response was generated
- **id_token** Identity Token

## 9. Identity token

The identity token is a JWT token that contains identity attributes about the user, for example name, date of birth or personal identity code. The token is signed by OP's RSA key. The signed token is embedded and encrypted into an JWE token using the service provider's public key.

To obtain the user attributes from the identity token you need to first decrypt the JWE token (`id_token`) received from the '/oauth/token' API. Decryption is done using the Service Provider private RSA key. The decrypted JWS token is signed using OP's RSA certificate to prevent tampering. Service Provider needs to verify that the signature is valid using the JWT library of your choice and the OP's public RSA key. The payload of the JWS token embedded in the JWE token contains user information.

The information received depends on the scope of identification request and on what attributes are available. Do note that not all sources of information have given name and family name available as separate attributes. The following attributes may be available currently:

- **birthdate**: Birth date
- **given_name**: Given name
- **family_name**: Family name
- **name**: Family name and given name
- **personal_identity_code**: The Finnish personal identity code

In addition there are these standard attributes:

- **auth_time**: Time of authentication in seconds since UNIX epoch
- **sub**: Subject identifier, not persistent, feel free to ignore

Example:

```json
{
  "sub": "a589adb6-1550-4b17-90c4-a19e8c3f3c0e",
  "name": "von Möttonen Matti Matias",
  "given_name": "Matti Matias",
  "family_name": "von Möttonen",
  "birthdate": "1900-01-01",
  "auth_time": 1519629890
}
```

## 10. GET /oauth/profile

This API is the OIDC UserInfo Endpoint. There is no need to call this if Service Provider has already got all the needed user information in processing the reply from the /oauth/token.
Service Provider can send request to the OIDC UserInfo Endpoint to obtain Claims about the End-User using an Access Token obtained from the /oauth/token API reply. The UserInfo Endpoint is an OAuth 2.0 [RFC6749] Protected Resource that complies with the OAuth 2.0 Bearer Token Usage [RFC6750] specification. The Access Token shall be sent using the Authorization header field as described below:

```
Authorization: Bearer eyJh[...]2A
```

where `eyJh[...]2A` is the access_token.

Example identification request:

`GET https://isb-test.op.fi/oauth/profile`

API errors:

| Error | Description |
| --- | --- |
| bad_request | invalid input parameters |
| unauthorized_client | e.g. authorization token is invalid |


The error and error description are shown on ISB with return link back to SP. In some cases however if certain library is used, an error is displayed on SP side and the error might be different than above.

The API returns json data. The information received depends on the scope of identification request and on what attributes are available. Do note that not all sources of information have given name and family name available as separate attributes. The following attributes may be available currently:

- **birthdate**: Birth date
- **given_name**: Given name
- **family_name**: Family name
- **name**: Family name and given name
- **personal_identity_code**: The Finnish personal identity code

In addition there is this standard attribute:

- **sub**: Subject identifier, not persistent, feel free to ignore

Example of returned data:
```json
{
  "sub": "1",
  "name": "von Möttonen Matti Matias",
  "personal_identity_code": "010101-011"
}
```

## 11. GET /.well-known/openid-configuration

We provide an optional OpenID Discovery metadata endpoint. It may be used to configure OAuth2 client implementations should they require it. The endpoint for production use is `https://isb.op.fi/.well-known/openid-configuration`. For testing please use the sandbox endpoint `https://isb-test.op.fi/.well-known/openid-configuration`.

## 12. JWKS

The JWKS endpoints are used to exchange public keys between parties. Both SP and ISB have a JWKS endpoint to publish their own public keys. The SP's JWKS endpoint URL has to be registered with OP in the production environment.

In the Sandbox there is no need to implement JWKS endpoint in the SP end as the ISB uses provided keys, but it is a good idea to implement functionality in the SP end to fetch the ISB signing key from the ISB's JWKS endpoint instead of using the provided keys because this is mandatory in the production.

SP needs to publish two public keys in it's JWKS endpoint:
- key for verifying both the signed /oauth/authorize request JWS token and the signed JWS token in client_assertion field in the /oauth/token request.
- key for identity token encrypting

ISB needs to publish one public key in it's JWKS endpoint:
- key for verifying the signed identity token

The ISB's JWKS endpoint is publicly available.

For example in Sandbox: `GET https://isb-test.op.fi/jwks/broker`.

Example response:

```json
{
  "keys":[
    {
      "kty":"RSA",
      "kid":"-DNF8ccKbmJ-oPVyeoIRaER4x8BI5Sqhvyr-UPk4Do4",
      "use":"sig",
      "n":"w1f2iqKttSHq8U93wGQMFyx11NtGMU_XOm8nitErtCRfdTUFlNmNq-4bbhn3Y9nY2yMqhJAJPubLVaTmdmAHy9NY45nrRVAXcIcazaKmcHLlNFNqFqMgrd3SwDE0nMB7SjwC0OwUBXIB97awWrcryZq79vIly9xtha63osbdXBSJI2E7CdOZaUBSo_jQl1Mp4Kn525yHCTqdrwze6u3JMqsKsrDojc_4HcFLQicHgaq5cKy1qSBO_D1P8PsDT7BRuHXqKewzAp4Tg-EYoVv32cEWXMJuCFG5fkImUh_oefY48I-Bp9eGaGV0H3nMF_xng0UZJ03-vAayetforXsmaw",
      "e":"AQAB"
    }
  ]
}
```

as an example with the provided keys the SP's JWKS endpoint's response looks like this:
```json
{
  "keys":[
    {
      "kty":"RSA",
      "kid":"dl-lgRcT7LhEkqbnod6QGBHl8veqgZenwdB3RV2OJkY",
      "use":"sig",
      "n":"ymeGHGpfRUdQe0VmPei3ARFBjlpVrK06RpUF3PJATGkNwBoX4j6LIJuacTnmLOiTlj84qy8ggLmoKZqai6JVsGQV-ThlCcRoujHCkNq8eebLBu0craNd62m-fXDfqrZ5TG7fTg6Da4Miv1rC2_hF5Cs3IukAJwHnbNSOY0Lq93jgV4fAt5BbpTttWKU_wBL-Pkei3Yd1pPoS9MmzLk_J8ZdoX72H_NzrXgO1AfoIFptdFMrV13jMZu5Y0NbggqPle1EQa_ErdLhqIOMfpllslxLPkZ_xq3-3ptogIFVOpnJ7CSLur-F-xUdl94-0kPu3jkGZFICRb9bkg1A1BHKiQw",
      "e":"AQAB"
    },
    {
      "kty":"RSA",
      "kid":"MfYGuONWQZabwwph02zJEqOQIPOV1PhEscgHch0QqD0",
      "use":"enc",
      "n":"xRXWHYRvsFJ6WGSiLSDZ5KgRHglSpTFbZsrZ_P6Sa9ZKeStOhcP0M4FO9ORdc12MsTPlFMIQy-6TiJXvZ8pxwcweFzaeGVBWtI_72waAHu5SSFnDpJ9SVRYCdCU95ONZAzNMaNNHTPivg5KgYL40yXZqGSCIApAEp7RcE6hm6PYdXLeWf_ATKNfVh9WMpMg49B5HWI7JPVjN8xVi73wjMKgKcReuX8T17HuF7wS0LZwWr80R8sXCevMKdUhah6YcF654eDsqYCEVrVAVOpdSMsmwkuoN0mnDmu8ltyCi-_46ibfmgDWFv_FIx-qAx92ADtBFYyhAiWEia4a67J7h6Q",
      "e":"AQAB"
    }
  ]
}
```

Note that the kid's listed in the JWKS endpoint must match to the kid's you specify in the JWS tokens. When using the sandbox environment, be careful to use the kid's mentioned in the above example and not one's you generate yourself.

## 13. Public Sandbox for customer testing

The public Sandbox differs from the production in three major ways.

- The Sandbox environment provides test data instead of real personal information.
- To use the Sandbox environment you need to use the separate API endpoints described above.
- Common shared credentials and client id are used for the Sandbox environment. Because the sandbox does not require registration all developers need to use the provided keys (instead of their own keys).
- SP do not need to implement JWKS-endpoint as the ISB uses provided keys.

These id's and keys are used for the Sandbox environment:

- **Client identifier**: saippuakauppias
- **Token encryption / decryption key**: See `sandbox-sp-encryption-key.pem`
- **Signing key**: See `sandbox-sp-signing-key.pem`

## 14. Service Provider code example

Currently there is PHP-based service provider demo application available. See https://github.com/op-developer/Identity-Service-Broker-integration-example .

## 15. Libraries for Service Provider

See the examples directory for examples on how to implement a service provider based on various libraries and languages.

## 16. Javascript

Bell is a simple library to take care of the OpenID Connect flow, but it needs to be modified slightly due to the signing purposes. See https://github.com/hapijs/bell . Currently we use forked bell library.

Node-jose can be used to decrypt and verify the identity token. See https://github.com/cisco/node-jose .

## 17. PHP

oauth2-client makes it simple to integrate your Service Provider application with OP ISB OpenID Connect flow. See https://github.com/thephpleague/oauth2-client .

Jose-php can be used to decrypt and verify the identity token. See https://github.com/nov/jose-php .

## 18. Extra material

To learn more about OpenID Connect, see the specification: https://openid.net/specs/openid-connect-core-1_0.html

## 19. Support
If you have feature requests or technical problems please submit an issue on Github.

For customer support please contact
- **corporate customers** +358 100 05151
- **email** verkkopainikkeet@op.fi

## 20. Sales

Please contact your own branch on contract matters.

## 21. Watching chages

The API might change in the future. Please enable watch-functionality as [instructed here](https://help.github.com/en/articles/watching-and-unwatching-repositories) to get notified when the API changes.
