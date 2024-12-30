# Changelog

## [0.2.0-SNAPSHOT] First public pre-release 

### Bug Fixes
* Fix Disclosure decoding (previously Disclosure were incorrectly decoded even when digest didn't match )

### Changes
* Use "aud" list of `{server}/key-shares/{shareID}?nonce={nonce}` URLs instead of custom "shareAccessData" json object.
* remove "kid" from JWT header (duplicate of "iss" in JWT body)
* remove "iat" and "exp" claims. Instead `nonce` creation time is checked by `cdoc2-shares-server`
* Move x5c certificate issuer check into `cdoc2-auth-token` module (from `cdoc2-shares-server`)