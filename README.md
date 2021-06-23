# wso2-jwt-grant-provisioning-handler

This custom JWT grant handler  would handle JIT provisioning(silent provisioning) for the JWT bearer grant if it is configured in the corresponding IDP.

To apply this Extended handler, please follow the steps below.

## Build

Clone the repository and in the directory where the pom file is located, issue the following command to build the project.

```
mvn clean install
```
## Deploy

After successfully building the project, the resulting jar file can be retrieved from the target directory. (the already built jar is included in the release section) copy the resulting jar to the <IS_HOME>/repository/components/lib/ directory.

Change the jwt-bearer grant configuration in the identity.xml file so the new handler class("org.wso2.custom.jwt.grant.JWTBearerProvisioningHandler") will be used for the "GrantTypeHandlerImplClass" as shown below.

```
<SupportedGrantType>
    <GrantTypeName>urn:ietf:params:oauth:grant-type:jwt-bearer</GrantTypeName>
    <GrantTypeHandlerImplClass>org.wso2.custom.jwt.grant.JWTBearerProvisioningHandler</GrantTypeHandlerImplClass>
    <GrantTypeValidatorImplClass>org.wso2.carbon.identity.oauth2.grant.jwt.JWTGrantValidator</GrantTypeValidatorImplClass>
</SupportedGrantType>
```
Restart the server.

## Testing

Configure JIT provisioning in the IDP configured for the JWT bearer grant.

<img width="1680" alt="Screen Shot 2021-06-23 at 9 09 47 AM" src="https://user-images.githubusercontent.com/47600906/123032006-e14ee800-d402-11eb-85b9-082cafbf5ddb.png">

Test the JWT bearer grant type.

```
curl --location --request POST 'https://localhost:9443/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic SHZNZUpPRUFnTUh5ZGdLNG5hRENTZlY2ZEcwYTpRX1BOME1qOXpYS3FVODJKMjNaaEVtNlZuZVFh' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
--data-urlencode 'assertion=eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoiVDFtWk9MSF94dXZKdGo2MFJaMXpPZyIsImF1ZCI6WyJVZWpqQzR6OVRzRlRFeFl3eHNNWEtzY0pZM0lhIiwiaHR0cHM6XC9cL2xvY2FsaG9zdDo5NDQzXC9vYXV0aDJcL3Rva2VuIl0sInN1YiI6InRoYXJha2F3aWpla29vbjJAZ21haWwuY29tIiwiY291bnRyeSI6IlNyaSBMYW5rYSIsImF6cCI6IlVlampDNHo5VHNGVEV4WXd4c01YS3NjSlkzSWEiLCJhbXIiOltdLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDRcL29hdXRoMlwvdG9rZW4iLCJncm91cHMiOlsiSW50ZXJuYWxcL2V2ZXJ5b25lIiwidGVzdHJvbGUiXSwiZXhwIjoxNjI0Mzk2NTAwLCJpYXQiOjE2MjQzOTI5MDAsIm5vbmNlIjoidnN4Z2hlM2QzdHIiLCJzaWQiOiIwNTRmNjBjMi01YTljLTRiMWEtOTI4Mi0xMjkxNGY5OTcwOGUifQ.dBhyfHkwcUfTF8F5C2pPuDFBBdYthwjWqhG6vuUtb2vMfW2GGFU4Z_49JFqgO2ivVJZJ7OzBwGgyZM9qB4zA8n7mIkoQQ4tF_nuhhZACDOj1AtDl00etH4fuHqDbO5d8iqLuGvbXzqX5z2S1ROradE39ui5XpQLHZIGsYg94kTdxxrzlznNNREp1zYbAwoRvhSPDS-7a8UXvz7pm3WPHOugC5AsuXmj0sav-i7x5gcVrL3qJrA3XanZx_eoYega4IvPW2WAVd-Q0VSMopew5iyLnFdtu3y8JTQFiXY8ibkiIp1mmk1w127AWrX4B4x99ha6JuGcc5LGsSCAZ585qFg' \
--data-urlencode 'scope=openid'
```

The user and the claims configured would be provisioned. 

When building the token, if the token needs to be populated with the claims of the provisioned user, the "Assert identity using mapped local subject identifier" option should selected at the service provider and the relevant claims should be added as requested claims.

<img width="1680" alt="Screen Shot 2021-06-23 at 9 12 24 AM" src="https://user-images.githubusercontent.com/47600906/123032256-46a2d900-d403-11eb-987a-0f0cc50369a6.png">
