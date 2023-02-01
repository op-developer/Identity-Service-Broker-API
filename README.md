# Service Provider API for OP Identity Service Broker

2023-01-30

OP Identification Service Broker allows Service Providers to implement strong electronic identification (Finnish bank credentials, Mobile ID) easily to websites and mobile apps via single API.

To identify the user the Service Provider (your website) redirects the user to the Identification Service Broker (OP) with an authorization request. The user chooses the Identity Provider (a bank or Mobile ID) and is redirected there where he/she authenticates with his/her own credentials. OP will process the authentication result, and return the user to your website with verified information about the identity of the user.

### Sandbox users

OP Identity Service Provider does not require registration and uses fixed credentials (Client ID & encryption keys). __See section 15__.

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
12. GET /.well-known/openid-federation
13. The Entity Statement of Service Provider
14. JWKS
15. Public Sandbox for customer testing
16. Service Provider code examples
17. Libraries for Service Provider
18. Javascript
19. PHP
20. Java
21. Python
22. Extra material
23. Support
24. Pricing
25. M72b changes
26. Watching changes

## 1. Definitions

- **Entity Statement** metadata describing a service (SP or ISB).
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

* RSA key pair to sign requests

   Signing is used for verifying that requests originate from the SP. Signing is used in requests to two endpoints: /oauth/authorize and /oauth/token.

* RSA key pair to decrypt identity token

  OP will encrypt the identity token identifying the user with your public key and you will have to decrypt it with your private key. Keys are generated the same way as signing keys. Both encryption and signing public keys must be published in the SP's JKWS endpoint. Keep the private portions of these keypairs private.

* RSA key pair to sign Service Provider JWKS and the Entity Statement

  Signing is used for verifying that the JWKS originate from the SP or from the ISB. It is used to protect against hijacking the service.

To generate a 2048 bit RSA key run the command `openssl genrsa -out private.pem 2048` (you could replace the filename private.pem with one of your own choosing).

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
  "isbProviderInfo": "The OP Identity Service Broker is provided by OP Financial Group member cooperative banks and OP Corporate Bank plc.",
  "isbConsent": "During authentication, your personal ID and name are forwarded to the service provider.",
  "privacyNoticeText": "OP privacy notice",
  "privacyNoticeLink": "https://isb-test.op.fi/privacy-info?lang=en",
  "disturbanceInfo":
    {
      "header": "Notification of disruption",
      "text": "Network errors are causing some identifications to fail"
    }
}
```

Service Provider needs to use and display these fields: `isbProviderInfo`, `isbConsent`, `privacyNoticeText` and `privacyNoticeLink` on the UI.
The `privacyNoticeLink` is a hyperlink to the OP's privacy notice page and the `privacyNoticeText` is the localised link text according to `lang` query parameter. `DisturbanceInfo` is an optional field, which is only included in case a disturbance notification has been published. It gives information about identified disturbancies in the ISB service or in the Identity Providers. It is highly recommended to show this data to end users on the embedded Identity Service Broker UI. Both the `header` and the `text` are localised according to `lang` query parameter.

API errors:

| Error | Description | Action |
| --- | --- | --- |
| 404 Not found | the given client_id is not valid | error is shown on ISB |

## 7. GET/POST /oauth/authorize

To initiate the identification process the service provider directs the user to OP's OIDC endpoint either by redirect or by direct link. The request parameters are passed to the ISB in a signed JWS token. The token is sent in the GET request's query string as `request` parameter or in the POST request in `payload` as a JSON having structure `{request: <JWS_TOKEN>}`. The following parameters are supported in the authorization request as JWS token claims:

- **client_id** is the client identifier that specifies which service provider is asking for identification.
- **redirect_uri** specifies to which URI on your site (the service provider) you want the user to return to once identification is done.
Please note! In the production environment this URI must be registered beforehand with OP with the technical form to prevent other services misusing your credentials. In case the given redirect_uri parameter does not match the registered URI the /oauth/authorize endpoint returns an error and identification is finished. Redirect_uri must be using secure http schema.
- **response_type** value must be `code`.
- **scope** is a space separated list of scopes, or  basically sets of information requested. This must include `openid` and `personal_identity_code` and can optionally include also `profile`, `weak` and `strong`. Other scope values are rejected. For example `openid profile personal_identity_code` is accectable. The `profile` includes `name`, `given_name`, `family_name` and `birthdate`. If the Service Provider's purpose for identifying the user is to create new identification methods, i.e. for example to create an user account with username and password, then the Service Provider must report such purpose by adding either `weak` (for weak identifiers, for example password account) or `strong` (for strong electronic identification which is only for the officially licensed members of the Finnish Trust Network) to the scopes. Using weak or strong as a purpose may affect pricing and depends on your contract.

The following optional parameters (JWS token claims) may be used:
- **ui_locales** selects user interface language (`fi`, `sv` or `en`).
- **nonce** value is passed on to identity token as is. Use of `nonce` is highly recommended. It MUST contain at least 128 bits of entropy (for example at least 22 random characters AZ, a-z, 0-9). SP should make sure that the `nonce` attribute in the ID Token matches the value of sent `nonce`.
- **prompt** can be set to `consent` to indicate that the user should be asked to consent to personal data being transferred. In this case the Identity Service Broker will display a verification screen after the user has been authenticated.
- **state** is an opaque value you can use to maintain state between request and callback. Use of `state` is recommended. SP should make sure that the state-parameter it sends matches the state-parameter is receives in response to the redirect_uri.
- **ftn_idp_id** shall be delivered if the SP has the embedded Identity Service Broker UI. Parameter contains the id of the user chosen idp.
- **exp** the expiration time of the JWS token. This is seconds since UNIX epoch (UTC). Suggested time is 600 seconds in the future. If given, ISB checks that the JWS has not expired. If it has expired the ISB will respond with an error.
- **jti** JWT ID. A unique identifier for JWS tokens, which can be used to prevent reuse of the token. These identifiers must only be used once. If given, ISB checks if this `jti` has already been used and if it has ISB will respond with an error.
- **iss** Issuer. This must contain the client_id. If `jti` is given, this must be given as well.
- **ftn_spname**  Human readable name of the Service Provider the user is authenticating to. The name should identify the service in such a way that the user understands which service they are identifying to. It could for example be either the legal name of the organization or the trade name the user knows the service as. Because the ftp_spname parameter is processed by multiple different identity providers and may be shown on different user interfaces, including mobile apps, we recommend trying to keep the name reasonably short and avoiding unusual characters to make sure the name is displayed consistently.

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
| access_denied | e.g. validation error | redirected to the SP with error and error description|
| cancel | user cancel | redirected to the SP with error and error description|
| various validation errors | initial validation errors e.g. on invalid client_id, invalid or unsigned JWT etc.| error and error description are shown on ISB without return link back to SP |
| various errors during identification | OIDC, Saml2 or Tupas identification might go wrong for a number of reasons | error and error description are shown on ISB with return link back to SP |

In case the SP gets error code "cancel" with error description "user cancel" it means that the end user has canceled identification when the ISB hosted UI is being used. If the SP gets this error when using it's own embedded Identity Service Broker UI, it means that the end user has canceled identification on one of the Identity Providers, but might want to continue identification with another Identity Provider. In this case the SP should just simply display it's own embedded Identity Service Broker UI again.

## 8. POST /oauth/token

The actual user identity token from the token endpoint can be fetched using the /oauth/token API. The following parameters shall be included as request payload parameters:
- **code** authorization code, which was returned in succesful /oauth/authorize/ reply. Mandatory.
- **grant_type** needs to have value `authorization_code`. Mandatory.
- **client_assertion_type** must be `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
- **client_assertion** is a signed JWS authentication token. The JWS must be signed with the RS256 algorithm with SP's signing key.

Please make sure that you have header set to allow JSON response, and data in the POST request must be application/x-www-form-urlencoded

    headers=dict(
        Accept='application/json'
    )

The client_assertion is signed using the SP's signing key and must contain the following claims:
- **iss** Issuer. This must contain the client_id.
- **sub** Subject. This must contain the client_id.
- **aud** Audience. The aud (audience) Claim. This must match the ISB's token endpoint URL.
- **jti** JWT ID. A unique identifier for JWS tokens, which can be used to prevent reuse of the token. These identifiers must only be used once. ISB checks if this `jti` has already been used and if it has ISB will respond with an error.
- **exp** Expiration time for the token. This is seconds since UNIX epoch (UTC). Suggested time is 600 seconds in the future. ISB checks that the JWS has not expired. If it has expired the ISB will respond with an error.

Example identification request:

`POST https://isb-test.op.fi/oauth/token`

client_assertion is a JWS token and it might look like this (captured using the PHP based demo service provider example __See section 14__):
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzYWlwcHVha2F1cHBpYXMiLCJzdWIiOiJzYWlwcHVha2F1cHBpYXMiLCJhdWQiOiJodHRwczovL2lzYi10ZXN0Lm9wLmZpL29hdXRoL3Rva2VuIiwianRpIjoiNThkMWQ4ODk3OGIwYTY4MDliODg1NSIsImV4cCI6MTU2MjA3NjY1N30.GiIviTLsdTkrEfFNXnCQZnlJOMBss1bcxp_fOIJx9rrlLo3QHlW1KLIPv4RCusH7CVqiRyGaXMz5V0-eFBPMrOLU68N1GxRIaJErZCUyU1uasP-qdEANJExwbrvOJ4Xt0wT51BVVdNwUgchkbjKY62wjj-ywHogpID2tI6vLS98uoWBq09sb_aZL9bLFLvNh85IJzAfOH748bxSByEtL0_-xTmYJBe4D_5Z5YDunkSjl4-SDts0ETl-0jdOPm8-ps2LdcFoGnwbNU_6Wp4JCggUqOP4F8JS-M1U0GeqEMvVLpURjQOAt06H-I-ppmnhAfibSeslmTw4FiTfVVaSHDA
```

The following is a snapshot of the payload inside the JWS token captured using the PHP based demo service provider example __See section 14__  :
```json
{
  "iss": "saippuakauppias",
  "sub": "saippuakauppias",
  "aud": "https://isb-test.op.fi/oauth/token",
  "jti": "58d1d88978b0a6809b8855",
  "exp": 1562076657
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

| Error code | Error | Error description | Description
| --- | --- | --- | --- |
| 400 Bad Request | unauthorized_client | invalid assertion | client_assertion or client_assertion_type are invalid |
| 400 Bad Request | invalid_request | client information fetching failed | client_id in request is unknown |
| 400 Bad Request | invalid_request | parameter validation failed | required request parameters missing or contains incorrect information |
| 400 Bad Request | invalid_request | invalid grant | e.g. authorization code already exchanged |


The error and error description are returned to SP as json together with error code.
```json
{
  "error":"unauthorized_client",
  "error_description":"invalid%20assertion"
}
```

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

- **iss**: Issuer. This should be the same as `issuer` key in .well-known/openid-configuration metadata. __See section 11__. SP can compare this value to the key value from metadata.
- **sub**: Subject identifier, not persistent, feel free to ignore
- **aud**: Audience this ID Token is intended for. It MUST contain the SP `client_id`
- **exp**: Expiration time in seconds since UNIX epoch on or after which the ID Token MUST NOT be accepted for processing.
- **iat**: Time at which the JWT was issued in seconds since UNIX epoch
- **auth_time**: Time of authentication in seconds since UNIX epoch
- **nonce**: Case sensitive string from the authentication request to associate an end-user with an ID token and to mitigate replay attacks. SP MUST verify that the `nonce` attribute value is equal to the value of the `nonce` parameter sent in the authentication request. In case there was no `nonce` parameter sent in the authentication request, this attribute is not used.
- **acr**:  The Authentication Context Class Reference string for this authentication transaction

Example:

```json
{
  "iss": "https://isb-test.op.fi",
  "sub": "59cc74ea-40d7-4000-85c6-e5f7c2e14205",
  "aud": "saippuakauppias",
  "exp": 1562076657,
  "iat": 1562076057,
  "acr": "http://ftn.ficora.fi/2017/loatest2",
  "nonce": "ab960b7480a00047fb0d23",
  "name": "von Möttonen Matti Matias",
  "given_name": "Matti Matias",
  "family_name": "von Möttonen",
  "birthdate": "1900-01-01",
  "personal_identity_code": "010100-969P",
  "auth_time": 1562076057
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

in case of error the ISB returns error code back to the SP with www-authenticate header. This header contains the error details as follows.

| Error code | www-authenticate header contents | description |
| --- | --- | --- |
| 401 Unauthorized | bearer | authorization header missing from request or invalid |
| 401 Unauthorized | bearer, error="invalid_token" | e.g. authorization token is invalid |
| 400 Bad Request | error="invalid_request",error_description="invalid_client" | Unknown client_id in profile request |


The API returns json data in succesful scenario. The information received depends on the scope of identification request and on what attributes are available. Do note that not all sources of information have given name and family name available as separate attributes. The following attributes may be available currently:

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

## 12. GET /.well-known/openid-federation

We provide an optional OpenId federation metadata endpoint containing the Entity Statement of the ISB. The metadata provided by this endpoint should not be automatically relied on by the SP, but should be manually reviewed. The endpoint for production use is `https://isb.op.fi/.well-known/openid-federation`. For testing please use the sandbox endpoint `https://isb-test.op.fi/.well-known/openid-federation`.

The payload is a base64 encoded and signed JSON web token and contains e.g. the URI of the signed JWKS endpoint. The key used for signing is the JWKS signing key.

OP will inform the Service Providers when the metadata is updated.

## 13. The Entity Statement of Service Provider

SP needs to provide metadata of its service to the ISB in the integration phase and when the SP is rotating its long-lived JWKS signing key. This metadata is not exchanged programmatically but SP will provide it to the OP as instructed separately by OP. The metadata is a signed JSON web token.

An example Entity Statement header and payload of the JSON web token:

header:
```json
{
  "alg": "RS256",
  "typ": "entity-statement+jwt",
  "kid": "QUGHzS05831lYsOB7_o-Nz2Ode2jmnmh5dJjDA5Q5SM"
}
```

payload:
```json
{
  "iss": "https://paras-saippuakauppias.com",
  "sub": "https://paras-saippuakauppias.com",
  "iat": 1675095869,
  "exp": 1990455869,
  "jwks": {
    "keys": [
      {
        "kty": "RSA",
        "kid": "QUGHzS05831lYsOB7_o-Nz2Ode2jmnmh5dJjDA5Q5SM",
        "use": "sig",
        "n": "wNIBGuvwCH6RmSGUySf-wi05VtQGQ6EJKKwD-JCraFMkj83O5sCIcnHFycrdqMuvMb67JEyTzSUjwwt52BZ4Bn_Cm71kF87pbgrBUdQR9Of5inp0LPFfWBptXCcBsny1303-2C7UxXrOJOzV3B2lBoEE9uTcgz3W7BaQtZiIB9vJNE-gTkDzD_ZYnepXJs19adewM7Qlt8k6iyGdWxSJlCmQ4eF8UcWugCaHvvHPBj0C9t7mJDfNiGSkxGrMzF50ymfLIwmj2BmaTLHpEpK4tReTq5eCCu7MeQIklv8egZGMjDiHpPHBcEgHZE_AAHL79RPS-he-UTi2dmgji70pfw",
        "e": "AQAB"
      }
    ]
  },
  "metadata": {
    "openid_relying_party": {
      "redirect_uris": [
        "https://paras-saippuakauppias.com/oauth/code"
      ],
      "application_type": "web",
      "id_token_signed_response_alg": "RS256",
      "id_token_encrypted_response_alg": "RSA-OAEP",
      "id_token_encrypted_response_enc": "A128CBC-HS256",
      "request_object_signing_alg": "RS256",
      "token_endpoint_auth_method": "private_key_jwt",
      "token_endpoint_auth_signing_alg": "RS256",
      "client_registration_types": [],
      "organization_name": "Saippuakauppias",
      "signed_jwks_uri": "https://paras-saippuakauppias.com/signed-jwks"
    }
  }
}
```

Encoded and signed JSON Web token:
```
eyJhbGciOiJSUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0Iiwia2lkIjoiUVVHSHpTMDU4MzFsWXNPQjdfby1OejJPZGUyam1ubWg1ZEpqREE1UTVTTSJ9.eyJpc3MiOiJodHRwczovL3BhcmFzLXNhaXBwdWFrYXVwcGlhcy5jb20iLCJzdWIiOiJodHRwczovL3BhcmFzLXNhaXBwdWFrYXVwcGlhcy5jb20iLCJpYXQiOjE2NzUwOTU4NjksImV4cCI6MTk5MDQ1NTg2OSwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJraWQiOiJRVUdIelMwNTgzMWxZc09CN19vLU56Mk9kZTJqbW5taDVkSmpEQTVRNVNNIiwidXNlIjoic2lnIiwibiI6IndOSUJHdXZ3Q0g2Um1TR1V5U2Ytd2kwNVZ0UUdRNkVKS0t3RC1KQ3JhRk1rajgzTzVzQ0ljbkhGeWNyZHFNdXZNYjY3SkV5VHpTVWp3d3Q1MkJaNEJuX0NtNzFrRjg3cGJnckJVZFFSOU9mNWlucDBMUEZmV0JwdFhDY0JzbnkxMzAzLTJDN1V4WHJPSk96VjNCMmxCb0VFOXVUY2d6M1c3QmFRdFppSUI5dkpORS1nVGtEekRfWlluZXBYSnMxOWFkZXdNN1FsdDhrNml5R2RXeFNKbENtUTRlRjhVY1d1Z0NhSHZ2SFBCajBDOXQ3bUpEZk5pR1NreEdyTXpGNTB5bWZMSXdtajJCbWFUTEhwRXBLNHRSZVRxNWVDQ3U3TWVRSWtsdjhlZ1pHTWpEaUhwUEhCY0VnSFpFX0FBSEw3OVJQUy1oZS1VVGkyZG1namk3MHBmdyIsImUiOiJBUUFCIn1dfSwibWV0YWRhdGEiOnsib3BlbmlkX3JlbHlpbmdfcGFydHkiOnsicmVkaXJlY3RfdXJpcyI6WyJodHRwczovL3BhcmFzLXNhaXBwdWFrYXVwcGlhcy5jb20vb2F1dGgvY29kZSJdLCJhcHBsaWNhdGlvbl90eXBlIjoid2ViIiwiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6IlJTMjU2IiwiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IlJTQS1PQUVQIiwiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuYyI6IkExMjhDQkMtSFMyNTYiLCJyZXF1ZXN0X29iamVjdF9zaWduaW5nX2FsZyI6IlJTMjU2IiwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2QiOiJwcml2YXRlX2tleV9qd3QiLCJ0b2tlbl9lbmRwb2ludF9hdXRoX3NpZ25pbmdfYWxnIjoiUlMyNTYiLCJjbGllbnRfcmVnaXN0cmF0aW9uX3R5cGVzIjpbXSwib3JnYW5pemF0aW9uX25hbWUiOiJTYWlwcHVha2F1cHBpYXMiLCJzaWduZWRfandrc191cmkiOiJodHRwczovL3BhcmFzLXNhaXBwdWFrYXVwcGlhcy5jb20vc2lnbmVkLWp3a3MifX19.trcVoUU0O_XxHJ8UcITxhQKQFfxfyrRozi8fX-fvGWE-PovXEzTqhtAm8W58COUy2tApyycgp2zpQZarA7NiA69WbOcfDJ45nBLDJVDWQ0JY-9tCCA4sa6g8caP91ap5VYm4hiytEjwWVYSt5kZhyY10_YsOn_RELzJVTW5mdCR067zjxXqko-rfrqgkM53tFgogKlgGtpQuMUphIUl14M9p3o1p9397sj1H9KXuOPOgxfmM8Df8WlqNfSF28DqI4O_-ABJb3VvpUuNZpgXknKSonvhgKhY8TFoS6DhN7iiGUE4H92XC2lNgWHACcqlFO1WL785TnaAl13jINGi1-Q
```

Fields of the Entity Statement header:
- **alg** is the algorithm of the JWKS signing key. RS256.
- **typ** type of the JWS. Use value `entity-statement+jwt`here.
- **kid** is the key id of the JWKS signing key.

Mandatory fields of the Entity Statement payload:
- **iss** The Entity Identifier of the issuer of the statement.
- **sub** the Entity Identifier of the subject. It SHOULD be the same as the issuer.
- **iat** The time the statement was issued.
- **exp** Expiration time on or after which the statement MUST NOT be accepted for processing.
- **jwks** A JSON Web Key Set (JWKS) representing the public part of the subject Entity's signing keys.
- **metadata.openid_relying_party.redirect_uris** a list of SP's redirect_uri's
- **metadata.openid_relying_party.application_type** use value `web` here.
- **metadata.openid_relying_party.id_token_signed_response_alg** use value `RS256` here
- **metadata.openid_relying_party.id_token_encrypted_response_alg** use value `RSA-OAEP` here
- **metadata.openid_relying_party.id_token_encrypted_response_enc** use value `A128CBC-HS256` here
- **metadata.openid_relying_party.request_object_signing_alg** use value `RS256` here
- **metadata.openid_relying_party.token_endpoint_auth_method** use value `private_key_jwt` here
- **metadata.openid_relying_party.token_endpoint_auth_signing_alg** use value `RS256` here
- **metadata.openid_relying_party.client_registration_types** use empty `[]` here
- **metadata.openid_relying_party.organization_name** is the name of the SP's organisation
- **metadata.openid_relying_party.signed_jwks_uri** is the uri of the SP's signed jwks endpoint

<span style="color:red">Note that it is possible for the SP to use wildcards in each of the redirect_uri's. This is helpful if there are a large number of those Urls. </span> As an example an SP has the following redirect_uri's:

- https://paras-saippuakauppias.com/service1
- https://paras-saippuakauppias.com/service1/en
- https://paras-saippuakauppias.com/service1/sv
- https://paras-saippuakauppias.com/service2

Instead of listing all those four redirect_uri's, you could just list one:

- https://paras-saippuakauppias.com/service*

ISB is then approving all the redirect_uri's matching the text before the wildcard * when validating the parameter in the /oauth/authorize request.

[For more information see the chapter 3.1 of the OpenID Connect Federation - document](https://openid.net/specs/openid-connect-federation-1_0.html#OpenID.Registration).

OP provides an easy-to-use online validator tool for the SP's Entity Statement JWS. The validity of the JWKS JWS can be checked as well and it is highly recommened to check them both. Validator checks that all the needed fields exists with meaningful values and it checks the signature in both the Entity Statement JWS and the JWKS JWS. Link to the validator: https://isb-test.op.fi/entity-statement-tester .

## 14. JWKS

<span style="color:red">Note that the non-signed ISB JWKS endpoints will be deprecated at the latest on May 2023. Signed JWKS endpoints are already available.</span>

The JWKS endpoints are used to exchange public keys between parties. Both SP and ISB have a JWKS endpoint to publish their own public keys. The JWKS has to be signed by the JWKS signing key. The SP's JWKS endpoint URL has to be registered with OP in the production environment.

In the Sandbox there is no need to implement JWKS endpoint in the SP end as the ISB uses provided keys, but SP must fetch the ISB signing key from the ISB's signed JWKS endpoint. SP needs to verify that the signature of the JWS matches the ISB JWKS signing key.

SP needs to publish two types of public keys in its JWKS endpoint:
- key for verifying both the signed /oauth/authorize request JWS token and the signed JWS token in client_assertion field in the /oauth/token request.
- key for identity token encrypting

ISB publishes one type of public key in it's JWKS endpoint:
- key for verifying the signed identity token

The ISB's JWKS endpoint is publicly available. Note that around the time of key rotation there are multiple sig-keys (both old and new) published at the same time.

For example in Sandbox: `GET https://isb-test.op.fi/jwks/broker-signed`.

Example response (Signed JSON web token):

```
eyJ0eXAiOiAiSldTIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaGsybDFaUmU0N2tWWDVta0lfeUJoNlR1ZWwtNXlJYk40ZDFVT2d6VTZtRSJ9.eyJrZXlzIjogW3siZSI6ICJBUUFCIiwgImt0eSI6ICJSU0EiLCAibiI6ICJ0a1RQUUQ1MUlaYWx1WDdUMzNWSkZfdF9xQmlKQ1JoRUJGbUw1OU9ZRjdXWWlOdndJaTFRUkxQSFdMUXFWQ1VFdnIzWVZZa1dTUXpEOXJ4M2xRZHNSTVlRdmdkVGs0NXZHTFVJeWplazFTcUVDYjljYnZnRlJydV9uTEF0WldUb2dXZ3BuSE41TV9ya0kwYWVUVmtXV1ZGZ0VValJ0TnZmNURBSnoyVFdmWEVlY0Q5dHluU0hna1RIU29SV3pqQkZNQW1LNjdxWEJtMV83T2VibmNGcFR1UENHUjRWRmQ1VGNQamJaX1AtUWRGMmttS29tbkM0NllXWFVOd2hvdjhIa2R3VkJvckNVWjFuM09fcE5TRWMtdHI1dmZXWUZSSzdfY3FUMDlRWndiVS15SXo0eFVFQjM4dlRHWXhYRGVYRWtnZGJaS3pVZ01vTnFDRmY1b1lxSFEiLCAidXNlIjogInNpZyIsICJraWQiOiAiLVZUZVJERHFLRWF1dnhqaUJCTnNXcXFVbnlBUUFYb19lQTJSZ3BKVXBncyJ9LCB7ImUiOiAiQVFBQiIsICJrdHkiOiAiUlNBIiwgIm4iOiAiMGRET2ZvQmREVWRSQmdXUkJzTDRRSzZUallQR0RiRVN4RFZmQ1ljd1Z0TVJOS1ZkM1RUdFM1UWRJR1IybENUUk0zTllPc0VwY3ZoNXpHaVZrY3UyekZ4ZnlZdzFCVVhCbjczZUhibnNhTFNnZjB2cEZvdGxqWWhsYVF2TXo3Tlh1X01yS0cxdXhRczVTN3R4RE9idjRONElkTzU5TXBZVUNvM0NIVGVhZW5GN2trUkJXYXFvWXpCZnhCQzBrNUM4blVjLWMydjNKTUZkTlVwLXg5UjJhSmxVNkUxOUtmdXJmQjRlUUlqT3VLV3BuQ0xPenZ6bTEwTTdaWVo0aUZXalJfQWpqVGppSGRlOEhKZTNIT1ZsVG1MSmdkUkQ1d3VmcWFzSWNXdmg1eDcwMnZmNVFtZnRvWXpXeFp4eGZVdEo1S3RjeVdpRzNFa2ZLQWpldmdxSkR3IiwgInVzZSI6ICJzaWciLCAia2lkIjogIllyZFFoX1RrQVR0bmlHVjRsTVAyZ01WVTR3MDl1ZWpPaFB1Z0hXVlR4eTQifSwgeyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogInVsQS1YR1NVNEZ0V09xVWNfUkoyNlVtLVI1OFotRUEyUGVTRFB1cXA0WG9pQ0JnOGZkTjFvWmhia1R4MHI4RFpGVEZHc1pkZzk3TU9fLUhyNHJrRkgxdHlpUXZyTC1jUGxKWkp3enNnbWQtZlQ1RTlub0hDclVRNno5VFdWUDAzMzB1SmVUVzVLeUw5ZVp5aHFqRlRWYUJLTlU1OXd5U0tiWERFTVBzZ3NBWEhVTC1weUhkaFpLdk5zQzBPZjVwQm1lX2hhelNJTGpmNDlyQlZfN1NZaWZUb1V1U05sSHgxQm91OTZWLTNobGw2UEQzSmVGeWlfVkhSWVU4MkRwekN2RVc1WF80UkJRRDhfbEFjNUpCNUl1WWVTYmFUQzYzdFVwQldsZGdSUGhFWkxaaWtUN0NNYW9sMkVhQ2VEdld4ZC0yTDNmdEFfNGxLZkNpdnowVnBRdyIsICJ1c2UiOiAic2lnIiwgImtpZCI6ICIwY1h2M3NyalphU3J3VFdRVlFBRnlTRmFHOWFyUHEwQ2g4S3VIZVNDaUJzIn1dLCAiaXNzIjogImh0dHBzOi8vaXNiLXRlc3Qub3AuZmkiLCAic3ViIjogImh0dHBzOi8vaXNiLXRlc3Qub3AuZmkiLCAiaWF0IjogMTY2NDIzNzg1NSwgImV4cCI6IDE2NjQyNDE0NTV9.FhMtdh1WQi7o0Xw1bCby6yM4oYVKCL32ZwspeTMf85GXbBVRZHMRo9FtOJc5uNcU4sqxty_5wUETZVa5g3kWiL00dkI4Qn0fZTtdWZa073IT3rkRKwQqZ5gZRtzeY47yUpZ3VCnLXKnOe3FHBBeGZp9pXf97UrpwUQTXHYQWxyLd1YNTFSFravOGVisOMzbmMct9Te91H5-w0-eNUUAHSEGF2C7_HDK4MCWNDki7g39WZYcX3f8RkU9GAC6ItMatBgazLxW_VQaZDRU6QKAyi2_T5dKY9zOh33hzRPG1JPo20mMej5UB5mNvxw5vPImz7BN3cfd9NPV2gH9RFNtrEV69uA8-aPlk6NOX7TSTbiZ3C9HdXC1SCSw-2acZbs13j99XqNONfIdMqrQly_OK9lk8ZMaFd7TiVvDRysfa5aM8Q52UqIWcHBZkzb-sEQvd1_YNn6pfFRFZuRS_C5nRVuFpz2VT1iKn8Qpgt7gpmygv8TYGiAS5QPieduCHN1dqM39UYavrFPHZjjj72ibU_4ymiEcnSXh5XaePNkJLiVfLZiwODVvQ_kPaNQh_nsZybDjfn62YryOiRzrQuiXS6q6A7Dr2o372DI02C-sqycN-MRk6OmjW3Km4c9jTUEeQJFr5Mp-EgEgME37RJ9e4LJxmxps9nrNvenUYYgGUMdk
```

example response decoded:

```json
{
  "keys": [
    {
      "e": "AQAB",
      "kty": "RSA",
      "n": "0dDOfoBdDUdRBgWRBsL4QK6TjYPGDbESxDVfCYcwVtMRNKVd3TTtS5QdIGR2lCTRM3NYOsEpcvh5zGiVkcu2zFxfyYw1BUXBn73eHbnsaLSgf0vpFotljYhlaQvMz7NXu_MrKG1uxQs5S7txDObv4N4IdO59MpYUCo3CHTeaenF7kkRBWaqoYzBfxBC0k5C8nUc-c2v3JMFdNUp-x9R2aJlU6E19KfurfB4eQIjOuKWpnCLOzvzm10M7ZYZ4iFWjR_AjjTjiHde8HJe3HOVlTmLJgdRD5wufqasIcWvh5x702vf5QmftoYzWxZxxfUtJ5KtcyWiG3EkfKAjevgqJDw",
      "use": "sig",
      "kid": "YrdQh_TkATtniGV4lMP2gMVU4w09uejOhPugHWVTxy4"
    },
    {
      "e": "AQAB",
      "kty": "RSA",
      "n": "ulA-XGSU4FtWOqUc_RJ26Um-R58Z-EA2PeSDPuqp4XoiCBg8fdN1oZhbkTx0r8DZFTFGsZdg97MO_-Hr4rkFH1tyiQvrL-cPlJZJwzsgmd-fT5E9noHCrUQ6z9TWVP0330uJeTW5KyL9eZyhqjFTVaBKNU59wySKbXDEMPsgsAXHUL-pyHdhZKvNsC0Of5pBme_hazSILjf49rBV_7SYifToUuSNlHx1Bou96V-3hll6PD3JeFyi_VHRYU82DpzCvEW5X_4RBQD8_lAc5JB5IuYeSbaTC63tUpBWldgRPhEZLZikT7CMaol2EaCeDvWxd-2L3ftA_4lKfCivz0VpQw",
      "use": "sig",
      "kid": "0cXv3srjZaSrwTWQVQAFySFaG9arPq0Ch8KuHeSCiBs"
    }
  ],
  "iss": "https://isb-test.op.fi",
  "sub": "https://isb-test.op.fi",
  "iat": 1664237855,
  "exp": 1664241455
}
```

as an example with the provided keys the SP's JWKS endpoint's response looks like this (Signed JSON web token):
```
eyJhbGciOiJSUzI1NiIsImtpZCI6IlFVR0h6UzA1ODMxbFlzT0I3X28tTnoyT2RlMmptbm1oNWRKakRBNVE1U00ifQ.eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJraWQiOiJkbC1sZ1JjVDdMaEVrcWJub2Q2UUdCSGw4dmVxZ1plbndkQjNSVjJPSmtZIiwidXNlIjoic2lnIiwibiI6InltZUdIR3BmUlVkUWUwVm1QZWkzQVJGQmpscFZySzA2UnBVRjNQSkFUR2tOd0JvWDRqNkxJSnVhY1RubUxPaVRsajg0cXk4Z2dMbW9LWnFhaTZKVnNHUVYtVGhsQ2NSb3VqSENrTnE4ZWViTEJ1MGNyYU5kNjJtLWZYRGZxclo1VEc3ZlRnNkRhNE1pdjFyQzJfaEY1Q3MzSXVrQUp3SG5iTlNPWTBMcTkzamdWNGZBdDVCYnBUdHRXS1Vfd0JMLVBrZWkzWWQxcFBvUzlNbXpMa19KOFpkb1g3MkhfTnpyWGdPMUFmb0lGcHRkRk1yVjEzak1adTVZME5iZ2dxUGxlMUVRYV9FcmRMaHFJT01mcGxsc2x4TFBrWl94cTMtM3B0b2dJRlZPcG5KN0NTTHVyLUYteFVkbDk0LTBrUHUzamtHWkZJQ1JiOWJrZzFBMUJIS2lRdyIsImUiOiJBUUFCIn0seyJrdHkiOiJSU0EiLCJraWQiOiJNZllHdU9OV1FaYWJ3d3BoMDJ6SkVxT1FJUE9WMVBoRXNjZ0hjaDBRcUQwIiwidXNlIjoiZW5jIiwibiI6InhSWFdIWVJ2c0ZKNldHU2lMU0RaNUtnUkhnbFNwVEZiWnNyWl9QNlNhOVpLZVN0T2hjUDBNNEZPOU9SZGMxMk1zVFBsRk1JUXktNlRpSlh2WjhweHdjd2VGemFlR1ZCV3RJXzcyd2FBSHU1U1NGbkRwSjlTVlJZQ2RDVTk1T05aQXpOTWFOTkhUUGl2ZzVLZ1lMNDB5WFpxR1NDSUFwQUVwN1JjRTZobTZQWWRYTGVXZl9BVEtOZlZoOVdNcE1nNDlCNUhXSTdKUFZqTjh4Vmk3M3dqTUtnS2NSZXVYOFQxN0h1Rjd3UzBMWndXcjgwUjhzWENldk1LZFVoYWg2WWNGNjU0ZURzcVlDRVZyVkFWT3BkU01zbXdrdW9OMG1uRG11OGx0eUNpLV80NmliZm1nRFdGdl9GSXgtcUF4OTJBRHRCRll5aEFpV0VpYTRhNjdKN2g2USIsImUiOiJBUUFCIn1dLCJpc3MiOiJodHRwczovL3BhcmFzLXNhaXBwdWFrYXVwcGlhcy5jb20iLCJzdWIiOiJodHRwczovL3BhcmFzLXNhaXBwdWFrYXVwcGlhcy5jb20iLCJpYXQiOjE2NzUwOTYyNTYsImV4cCI6MTY3NTE4NjI1Nn0.r3QTg7PskKH8dmZjOwPswqzh4Ae_Ee1Mm_s6YgKmNu48aLIYjhWZXJ6EGKKEX9aD2fT5jh29QTQ7ftnXijcg8UM53lC4aIVWZwNcrlYSATCUVI5HVlOgcPfjB8Pvj1AgK-9fhuQoSoWcEck1-KuGbYTUMAdU_wt26lEyf8ahXEJMantc5LZMq_xu9PLAOU4WiFt1wf1P3H4389fnzrN9uLrTHfQMbjxP56NiDbdYIC1cp4fFOf3v-_olA8ezQHypN-fbdy9VD1HJSPkNyca5-67QVntZjGI5ohJIv2j5My7nbOygn5xHuzoD2TQSDTgceXdDtFPL36X3Eq2rxt3MCw
```

response decoded:

header:
```json
{
  "alg": "RS256",
  "kid": "QUGHzS05831lYsOB7_o-Nz2Ode2jmnmh5dJjDA5Q5SM"
}
```
payload:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "dl-lgRcT7LhEkqbnod6QGBHl8veqgZenwdB3RV2OJkY",
      "use": "sig",
      "n": "ymeGHGpfRUdQe0VmPei3ARFBjlpVrK06RpUF3PJATGkNwBoX4j6LIJuacTnmLOiTlj84qy8ggLmoKZqai6JVsGQV-ThlCcRoujHCkNq8eebLBu0craNd62m-fXDfqrZ5TG7fTg6Da4Miv1rC2_hF5Cs3IukAJwHnbNSOY0Lq93jgV4fAt5BbpTttWKU_wBL-Pkei3Yd1pPoS9MmzLk_J8ZdoX72H_NzrXgO1AfoIFptdFMrV13jMZu5Y0NbggqPle1EQa_ErdLhqIOMfpllslxLPkZ_xq3-3ptogIFVOpnJ7CSLur-F-xUdl94-0kPu3jkGZFICRb9bkg1A1BHKiQw",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "MfYGuONWQZabwwph02zJEqOQIPOV1PhEscgHch0QqD0",
      "use": "enc",
      "n": "xRXWHYRvsFJ6WGSiLSDZ5KgRHglSpTFbZsrZ_P6Sa9ZKeStOhcP0M4FO9ORdc12MsTPlFMIQy-6TiJXvZ8pxwcweFzaeGVBWtI_72waAHu5SSFnDpJ9SVRYCdCU95ONZAzNMaNNHTPivg5KgYL40yXZqGSCIApAEp7RcE6hm6PYdXLeWf_ATKNfVh9WMpMg49B5HWI7JPVjN8xVi73wjMKgKcReuX8T17HuF7wS0LZwWr80R8sXCevMKdUhah6YcF654eDsqYCEVrVAVOpdSMsmwkuoN0mnDmu8ltyCi-_46ibfmgDWFv_FIx-qAx92ADtBFYyhAiWEia4a67J7h6Q",
      "e": "AQAB"
    }
  ],
  "iss": "https://paras-saippuakauppias.com", // this contains the URI of the SP
  "sub": "https://paras-saippuakauppias.com", // this contains the URI of the SP
  "iat": 1675096256, // the time the keys were created
  "exp": 1675186256 // Expiration time on or after which the keys MUST NOT be accepted for processing
}
```

Note that these fields are mandatory:
- keys
- iss
- sub

These fields are optional but highly recommended
- iat
- exp

[For more information See the chapter 4.1 of the OpenID Connect Federation - document](https://openid.net/specs/openid-connect-federation-1_0.html#OpenID.Registration).

Note that the kid's listed in the JWKS endpoint must match to the kid's you specify in the JWS tokens. When using the sandbox environment, be careful to use the kid's mentioned in the above example and not one's you generate yourself and make sure to use the given JWKS signing key. Because the sandbox environment uses predefined keys the ISB does not call your JWKS endpoint. If you wish to test your JWKS endpoint, you can do it by comparing your output against the example output above.

About ISB key rotation.

ISB rotates the signing key once a week in production. To help testing, the signing key is rotated daily in the Sandbox environment. The figure below illustrates the lifecycle of the keys.

![Key rotation](./key_rotation.png?raw=true)

- CREATE, new key is created
- WARM-UP, key is published in the JWKS but not in use
- NORMAL USE, key is in use
- COOLDOWN, key is still published in the JWKS and is not in use
- TAIL, key is not published anymore in the JWKS, key is not in use
- DELETION, key is deleted

Caching the keys fetched from the JWKS endpoint is a good idea, but make sure that the refresh mechanism supports the ISB lifecycle, and there is a forced cache refresh in case key is not found.

## 15. Public Sandbox for customer testing

The public Sandbox differs from the production in these major ways.

- The Sandbox environment provides test data instead of real personal information.
- To use the Sandbox environment you need to use the separate API endpoints described above.
- Common shared credentials and client id are used for the Sandbox environment. Because the sandbox does not require registration all developers need to use the provided keys (instead of their own keys). Production client id does not work in Sandbox.
- SP do not need to implement JWKS-endpoint in Sandbox as the ISB uses provided keys.
- redirect_uri does not have to agreed with OP in Sandbox.
- ftn_spname is whitelisted in the Sandbox with the following three values. Only these are approved and pre-registered with the OP ISB:
  - "Saippuaa kansalle"
  - "Soap for the people"
  - "tvål för folket"
- the /api/embedded-ui/{client_id} endpoint always returns disturbanceInfo field in the returned Json data. It either contains real disturbance information of the Sandbox or contains a placeholder text: "This is a placeholder for disturbance information to help implementation". This is to help implementation of the UI.

These id's and keys are used for the Sandbox environment:

- **Client identifier**: saippuakauppias
- **Token encryption / decryption key**: See `sandbox-sp-encryption-key.pem`
- **Signing key**: See `sandbox-sp-signing-key.pem`
- **SP JWKS signing key**: See `sandbox-sp-entity-signing-key.pem`
- **public ISB JWKS signing key**: See `sandbox-isb-entity-signing-pubkey.pem`

## 16. Service Provider code examples

OP Provides the following Service Provider demo applications:

- PHP-based: https://github.com/op-developer/Identity-Service-Broker-integration-example
- Java-based: https://github.com/op-developer/Identity-Service-Broker-integration-java-example
- Python-based: https://github.com/op-developer/Identity-Service-Broker-integration-python-example
- Typescript-based: https://github.com/op-developer/Identity-Service-Broker-integration-typescript-example

## 17. Libraries for Service Provider

See the examples directory for examples on how to implement a service provider based on various libraries and languages.

## 18. Javascript

Node-jose can be used to decrypt and verify the identity token. See https://github.com/cisco/node-jose .

Broadly speaking we do not currently advise use of generic OpenID Connect libraries. They often lack support for signed authorization requests and encrypted ID tokens, requiring you to extend them for use with our API. In such situations it is typically easier to implement your service provider with libraries offering slightly lower level of abstraction, as demonstrated by our code examples.

## 19. PHP

oauth2-client makes it simple to integrate your Service Provider application with OP ISB OpenID Connect flow. See https://github.com/thephpleague/oauth2-client .

Jose-php can be used to decrypt and verify the identity token. See https://github.com/nov/jose-php .

## 20. Java

Nimbus JOSE+JWT is a Java library for Javascript Object Signing and Encryption (JOSE) and JSON Web Tokens (JWT). See https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt . This library is used in the Java based integration example. __See section 16__

## 21. Python

JWCrypto is an Python library implementation of the Javascript Object Signing and Encryption (JOSE) Web Standards as they are being developed in the JOSE IETF Working Group and related technology. See https://github.com/latchset/jwcrypto

## 22. Extra material
- To learn more about the OP Identity Service Broker, see: https://isb-test.op.fi/about?lang=en
- To learn about the OP Identity Service Broker Privacy Notice, see: https://isb-test.op.fi/privacy-info?lang=en
- To learn more about OpenID Connect, see the specification: https://openid.net/specs/openid-connect-core-1_0.html

## 23. Support
If you have feature requests or technical problems please submit an issue on Github.

For customer support please contact
- **corporate customers** +358 100 05151
- **email** verkkopainikkeet@op.fi

## 24. Sales

Please contact your own branch on contract matters.

## 25. M72b changes

The regulation M72b for the strong electronic identification services by Traficom has changed and it came into effect on 1st of June 2022. However the period of transition is one year, which means that these changes have to be taken into use no later than during May 2023. Biggest change is the introduction of the OIDC federation.

These are the changes from Service Provider point of view:
- introduction of ftn_spname
- Service Provider needs to create a new key for signing it's JWKS keys
- Service Provider needs to replace its current JWKS endpoint with a signed JWKS endpoint
- Service Provider needs to create an Entity Statement containing the public signing key and exchange it with OP.
- ISB is also replacing its JWKS endpoint with a signed one. Service Provider needs to start using the ISB's signed JWKS endpoint and to verify the signature of the ISB OP JWKS.

## Introduction of ftn_spname

The new optional **ftn_spname** parameter in the /oauth/authorize request makes it possible for the Service Provider to specify a human readable name of the Service Provider to be displayed during the identification process. Typically it should be localised to the same language as indicated by the **ui_locales** parameter. See more information about the **ftn_spname** parameter in the chapter 7. This is how the **ftn_spname** with value `Saippuakauppias`is displayed during the identification.

<img src="spname.png" alt="ftn_spname displayed" width="400"/>

<span style="color:red">Note that the **ftn_spname** parameter values have to be agreed with OP before succesful usage.</span> ISB will only approve a value, which has been agreed upon. In case SP uses a value, which has not been agreed upon or does not use this optional parameter at all the ISB is using the legal name of the Service Provider company.



## Service Provider needs to create a new key for signing it's JWKS keys

Service Provider needs to create a new RSA key for signing its JWKS and the Entity Statement. This key is typically a long-lived key. The private part of this key shall be kept as secret and stored securely.

## Service Providers signed JWKS

So far both the OP ISB and the SP have published its public keys in the JWKS endpoint. This continues as such in the future, but the payload will be a signed JSON web token instead of json. See the modified chapter 14.

## Service Provider Entity Statement

Service Provider needs to create an Entity Statement and exchange it with the OP. Easiest way is to implement the Entity Statement creation programmatically like in the integration examples. This will also minimize human errors e.g. when rotating the signing key. Entity Statement is described in the chapter 13.

It is possible to check the validity of the Service Provider's Entity Statement as well as signed JWKS online. See chapter 13 for more details.

## 26. Watching changes

The API might change in the future. Please enable watch-functionality as [instructed here](https://help.github.com/en/articles/watching-and-unwatching-repositories) to get notified when the API changes.
