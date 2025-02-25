# Changelog

## [0.3.3] First public release

## [0.3.3-SNAPSHOT] Improvements to 0.3.2-SNAPSHOT

### Changes
* Add slf4j-api and change logback-classic scope to test.

## [0.3.2-SNAPSHOT] Bugfixes 0.3.1-SNAPSHOT

### Bug Fixes
* Fix "java.lang.ClassNotFoundException: org.bouncycastle.cert.jcajce.JcaX509CertificateHolder" 
  when validating "ES256" JWT tokens. Nimbus library depends (optional) on 
  `org.bouncycastle:bcpkix-jdk18on:1.80` when parsing certificates with EC keys.

## [0.3.1-SNAPSHOT] Improvements to 0.3.0-SNAPSHOT

### Changes
* add `EtsiIdentifier.PREFIX` const
* make `AuthTokenCreator.sign(JWSSigner, JWSAlgorithm)` public to support JWSSigner with multiple algorithms.

### Bug Fixes
* Fix EtsiIdentifierTests
* When verifying auth-token with EC certificate, determine EC curve from certificate instead of using hard-coded `P256`
* Previously first RSA JWSAlgorithm was selected from JWSSigner supported algorithms (that happened to be `RS256`).
  RSA JWT algorithm must now be explicitly specified or JWSSigner must support single algorithm (like SIDAuthJWSSigner does)


## [0.3.0-SNAPSHOT] Support for signing with EC keys

### Features

* Support for signing and verifying auth-token with EC keys (ES256) to support Mobile-ID

## [0.2.0-SNAPSHOT] First public pre-release 

### Bug Fixes
* Fix Disclosure decoding (previously Disclosure were incorrectly decoded even when digest didn't match )

### Changes
* Use "aud" list of `{server_base_url}/key-shares/{shareID}?nonce={nonce}` URLs instead of custom "shareAccessData" json object.
* remove "kid" from JWT header (duplicate of "iss" in JWT body)
* remove "iat" and "exp" claims. Instead `nonce` creation time is checked by `cdoc2-shares-server`
* Move x5c certificate issuer check into `cdoc2-auth-token` module (from `cdoc2-shares-server`)