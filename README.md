# cdoc-auth

* Implements `x-cdoc2-auth-ticket` header parameter for 
  [GET /key-shares/\${shareId}](https://github.com/open-eid/cdoc2-openapi/cdoc2-key-shares-openapi.yaml)
* Supports ES256 and RS256 algorithms required to support [Mobile-ID](https://github.com/SK-EID/MID) 
  and [Smart-ID](https://github.com/SK-EID/smart-id-documentation) (other algorithms not tested)

Used by:

* [cdoc2-java-ref-impl](https://github.com/open-eid/cdoc2-java-ref-impl) for auth-ticket creation
* [cdoc2-shares-server](https://github.com/open-eid/cdoc2-shares-server) for auth-ticket validation


## Building
[![Java CI with Maven](https://github.com/open-eid/cdoc2-auth/actions/workflows/maven.yml/badge.svg)](https://github.com/open-eid/cdoc2-java-ref-impl/actions/workflows/maven.yml)

CDOC2 has been tested with JDK 17 and Maven 3.8.8

```
mvn clean install
```

## Get from GitHub package repo


Configure github package repo access
https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry#authenticating-with-a-personal-access-token

Example `<profile>` section of `settings.xml` for using `cdoc2-auth-token`:
```xml
  <profile>
      <id>github</id>
      <repositories>
        <repository>
          <id>central</id>
          <url>https://repo1.maven.org/maven2</url>
        </repository>
        <repository>
          <id>github</id>
          <url>https://maven.pkg.github.com/open-eid/cdoc2-auth</url>
        </repository>
      </repositories>
  </profile>
```

Note: When pulling, the package index is based on the organization level, not the repository level.
https://stackoverflow.com/questions/63041402/github-packages-single-maven-repository-for-github-organization

So defining single Maven package repo from `open-eid` is enough for pulling cdoc2-* dependencies.

Use in Maven pom.xml:

```xml
  <dependency>
    <groupId>ee.cyber.cdoc2</groupId>
    <artifactId>cdoc2-auth-token</artifactId>
    <version>0.3.3-SNAPSHOT</version>
  </dependency>
```

## Releasing

### Versioning 

cdoc2-auth uses [semantic versioning](https://semver.org/).

### GitHub release

[Create release](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository#creating-a-release).
It will trigger `maven-release.yml` workflow that will deploy Maven packages to GitHub Maven package repository
and build & publish maven packages.



## cdoc2.auth-token.v1 examples

* Official documentation: [SD-JWT based CDOC2 authentication protocol](https://open-eid.github.io/CDOC2/2.0-Draft/03_system_architecture/ch06_ID_authentication_protocol/) (TODO: update to final 2.0, when available)
* `/key-shares` OAS specification can be found here: https://github.com/open-eid/cdoc2-openapi

In short, cdoc2 key-shares auth ticket is used to authenticate against multiple key-share servers by signing
authenticated data ones and not revealing auth data to other servers. For this 
[SDJWT](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) format is used.

SdJWT in encoded format:
<pre>
&lt;JWT_header&gt;.&lt;JWT_payload&gt;.&lt;JWT_signature&gt;~&lt;Disclosure1&gt;~&lt;Disclosure2&gt;~
</pre>

To decode sd-jwt use [sdjwt.org](https://sdjwt.org/)

To generate auth-ticket client must first generate `nonce` for each `KeyShare` object accessed using
[\${serverBaseUrl}/key-shares/\${shareId}/nonce](https://github.com/open-eid/cdoc2-openapi/blob/facc1371e3dc39a426541f8a153083c8a6d4539c/cdoc2-key-shares-openapi.yaml#L87) endpoint.

### JWT_header

JWT header for cdoc2 auth ticket:
```json
{
  "typ": "vnd.cdoc2.auth-token.v1+sd-jwt",
  "alg": "RS256"
}
```

### JWT_payload
JWT payload:
```json
{
  "iss": "etsi/PNOEE-30303039914",
  "aud": [
    "https://css.ria.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3?nonce=59b314d4815f21f73a0b9168cecbd5773cc694b6",
    "https://ccs.another-organization.org:443/key-shares/5BAE4603-C33C-4425-B301-125F2ACF9B1E?nonce=9d23660840b427f405009d970d269770417bc769"
  ]
}
```

Nonce value was acquired using [\${serverBaseUrl}/key-shares/\${shareId}/nonce](https://github.com/open-eid/cdoc2-openapi/blob/facc1371e3dc39a426541f8a153083c8a6d4539c/cdoc2-key-shares-openapi.yaml#L87) endpoint.

Before signing, "aud" will be replaced with a digest value as specified in 
[sd-jwt specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/):
```json
{
  "iss": "etsi/PNOEE-30303039914",
  "_sd": [
    "V5_DrlDm-FXeGPdcMZQrB7EZPEO98URIAYvykgWHZr0"
  ],
  "_sd_alg": "sha-256"
}
```

Values of "aud" will be selectively disclosed to CSS server that has shareID accessed.

sd-jwt (auth ticket) for accessing key-share `https://css.ria.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3` 
with `nonce` `59b314d4815f21f73a0b9168cecbd5773cc694b6`

(use [sdjwt.org](https://sdjwt.org/) to decode)
```
eyJ0eXAiOiJ2bmQuY2RvYzIuYXV0aC10b2tlbi52MStzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJldHNpL1BOT0VFLTMwMzAzMDM5OTE0IiwiX3NkIjpbIlY1X0RybERtLUZYZUdQZGNNWlFyQjdFWlBFTzk4VVJJQVl2eWtnV0hacjAiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.U31NbtFFn9CxdsQGuiQN0K_HPcJGdN1GEVepkAVGWk4Ug0cjWjZ79l6ghSqSD-tnlNJ3_yAcXJfihhmhCNFkPapupds-74U52RuwjN5iPJAI9BsvgXuXCXojQbF8pm2pwx9S7Cdxwoog22xMwwVl8_qU7f0k3XQjjQsC3Yqv5NA9iFCDnedkprwGozPEDf8VdU0O8zholhfDuMZcsjM540Cz795ab3s3MSscfG0E62ZqK1w6fi_Tbvh81KbFJtKM9JEZdwUGX69QrePBrqpb8Kmww5C-fjiFKRK7U02GbfccnBmaMAZ1KNTegez0ZEEBxk1m1cmSfcQ8vO6Cq539y3OJUVlytZ6ObD47Yx2PTuFGCtCVbPSx0q9VEVvPSgT3HuAHH1IIi7sakuznRzktUD8k_iJ86OJLJ6TN8_IZ9nzeTKbwlsqiY6g5B_ISdEiwhZqB_Rc8d3p7I70nQaYT9980jAEJvdKiRM2RvG4dYs7C4-hi7hXVrOgVvcFy0GpOb8pVy4N6Z6n1q9tQll90HRFo79CtY16u8Zc5AwUC9vifb7N7GO4ZQnhd4YIiX5FXYTMYXRY9MfMfswikCSrtXddBScQ-tOcacZ920fceMsrrrPHzKfOUd_G2GFwCFW2D2sPz5FOEWt5Cp6Xq1jPgITNvfJyFtEyeZlPjD8LDIfE~WyJFVjVmZjNrM1FQUlVaZ0ltaGRJUlhRIiwiYXVkIixbeyIuLi4iOiJsUkVVLURBY2FHTnpGVnkwVHVSSGM2TjZfRFBPSGxqQUxfWldpOVkzc0trIn0seyIuLi4iOiI2Q2lLSUpGZkYtSEhxQ1VuRm41dnY4T3RlLU5mbG5KWlYyS1VYMmk3VUNNIn1dXQ~WyJjak0yMGEwdUxROUdPaXExb3NMeXBBIiwiaHR0cHM6Ly9jc3MucmlhLmVlOjQ0My9rZXktc2hhcmVzLzlFRTkwRjJELUQ5NDYtNEQ1NC05QzNELUY0QzY4RjdGRkFFMz9ub25jZVx1MDAzZDU5YjMxNGQ0ODE1ZjIxZjczYTBiOTE2OGNlY2JkNTc3M2NjNjk0YjYiXQ~
```

sd-jwt above has 2 Disclosures (base64 encoded data between `~`)

#### Disclosure 1 (digest `V5_DrlDm-FXeGPdcMZQrB7EZPEO98URIAYvykgWHZr0`):
`WyJFVjVmZjNrM1FQUlVaZ0ltaGRJUlhRIiwiYXVkIixbeyIuLi4iOiJsUkVVLURBY2FHTnpGVnkwVHVSSGM2TjZfRFBPSGxqQUxfWldpOVkzc0trIn0seyIuLi4iOiI2Q2lLSUpGZkYtSEhxQ1VuRm41dnY4T3RlLU5mbG5KWlYyS1VYMmk3VUNNIn1dXQ`:
`["EV5ff3k3QPRUZgImhdIRXQ","aud",[{"...":"lREU-DAcaGNzFVy0TuRHc6N6_DPOHljAL_ZWi9Y3sKk"},{"...":"6CiKIJFfF-HHqCUnFn5vv8Ote-NflnJZV2KUX2i7UCM"}]]`

#### Disclosure 2 (digest `lREU-DAcaGNzFVy0TuRHc6N6_DPOHljAL_ZWi9Y3sKk`):

`WyJjak0yMGEwdUxROUdPaXExb3NMeXBBIiwiaHR0cHM6Ly9jc3MucmlhLmVlOjQ0My9rZXktc2hhcmVzLzlFRTkwRjJELUQ5NDYtNEQ1NC05QzNELUY0QzY4RjdGRkFFMz9ub25jZVx1MDAzZDU5YjMxNGQ0ODE1ZjIxZjczYTBiOTE2OGNlY2JkNTc3M2NjNjk0YjYiXQ`:
`["cjM20a0uLQ9GOiq1osLypA","https://css.ria.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3?nonce\u003d59b314d4815f21f73a0b9168cecbd5773cc694b6"]`

Note: Disclosure 1 also contains digest `6CiKIJFfF-HHqCUnFn5vv8Ote-NflnJZV2KUX2i7UCM`, but it is 
not disclosed as ShareId belongs to another key-share-server. 

Content of Disclosures:

| Digest                                        | Salt                     | Claim Name | Claim Value                                                                                                                  |
|-----------------------------------------------|--------------------------|------------|------------------------------------------------------------------------------------------------------------------------------|
| `V5_DrlDm-FXeGPdcMZQrB7EZPEO98URIAYvykgWHZr0` | `EV5ff3k3QPRUZgImhdIRXQ` | `aud`      | `[{"...":"lREU-DAcaGNzFVy0TuRHc6N6_DPOHljAL_ZWi9Y3sKk"},{"...":"6CiKIJFfF-HHqCUnFn5vv8Ote-NflnJZV2KUX2i7UCM"}]`              |
| `lREU-DAcaGNzFVy0TuRHc6N6_DPOHljAL_ZWi9Y3sKk` | `cjM20a0uLQ9GOiq1osLypA` | (no value) | `https://css.ria.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3?nonce\u003d59b314d4815f21f73a0b9168cecbd5773cc694b6` |

Note: `Digest` can be calculated using
```bash
echo -n WyJFVjVmZjNrM1FQUlVaZ0ltaGRJUlhRIiwiYXVkIixbeyIuLi4iOiJsUkVVLURBY2FHTnpGVnkwVHVSSGM2TjZfRFBPSGxqQUxfWldpOVkzc0trIn0seyIuLi4iOiI2Q2lLSUpGZkYtSEhxQ1VuRm41dnY4T3RlLU5mbG5KWlYyS1VYMmk3VUNNIn1dXQ |openssl dgst -sha256 -binary|base64url|tr -d '=\n'
```

After disclosing Disclosures from sd-jwt, JWT body will be:

```json
{
  "iss":"etsi/PNOEE-30303039914",
  "aud":["https://css.ria.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3?nonce=59b314d4815f21f73a0b9168cecbd5773cc694b6"]
}
```

Other rules to validate auth ticket:

[Verifying SD-JWT (verifying authentication ticket)](https://open-eid.github.io/CDOC2/2.0-Draft/03_system_architecture/ch06_ID_authentication_protocol/#verifying-sd-jwt-verifying-authentication-ticket)

For additional details see tests in `src/test/java/`

