package ee.cyber.cdoc2.auth;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectDecoder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jose.shaded.gson.reflect.TypeToken;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.StringReader;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class to validate cdoc2 auth tokens, created by {@link AuthTokenCreator}
 * Validated data has the following structure:
 * {@link AuthTokenVerifier#getVerifiedClaims(String)}:
 * <code>
 *  {
 *      shareAccessData=[{serverNonce=59b314d4815f21f73a0b9168cecbd5773cc694b6,
 *          shareId=9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3,
 *          serverBaseURL=https://cdoc-ccs.ria.ee:443/key-shares/}],
 *       iss=etsi/PNOEE-48010010101,
 *      exp=1728651637,
 *      iat=1728651577,
 *      sharedAccessDataPOJO=ee.cyber.cdoc2.auth.ShareAccessData
 *  }
 *  * </code>
 */
public class AuthTokenVerifier {
    private static final Logger log = LoggerFactory.getLogger(AuthTokenVerifier.class);

    private static final Logger tokens_log = LoggerFactory.getLogger("tokens");

    /**
     * Verify JWT signature, map disclosures data to signed digests. Return verified data. User must verify that matches
     * data accessed
     * @param token sdjwt created by {@link AuthTokenCreator}
     * @return verified claims JsonObject
     * @throws VerificationException when token doesn't verify or missing/unsupported data
     * @throws ParseException        If the string couldn't be parsed to a valid signed JWT.
     * @throws JOSEException
     */
    public static Map<String, Object> getVerifiedClaims(String token) throws VerificationException, JOSEException, ParseException {
        SDJWT sdJwt = SDJWT.parse(token);

        String jwt = sdJwt.getCredentialJwt();
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        JWSHeader header = signedJWT.getHeader();

        if (!JWSAlgorithm.PS256.equals(header.getAlgorithm())) { //RSASSA-PSS using SHA-256 hash algorithm and MGF1
            throw new VerificationException("Algorithm not supported: "+ header.getAlgorithm());
        }

        if (header.getType() == null ||
            !Constants.TYPE.equals(signedJWT.getHeader().getType().toString())
        ) {
            throw new VerificationException("Unsupported typ "+ header.getAlgorithm());
        }

        if (header.getJWK() == null) {
            throw new VerificationException("Expected jwk in header");
        }

        if (!KeyType.RSA.equals(header.getJWK().getKeyType())) {
            throw new VerificationException("Expected jwk.kty to be RSA " + header.getJWK().getKeyType());
        }

        RSAKey rsaPubKey = signedJWT.getHeader().getJWK().toRSAKey();
        //TODO: check cert for SID
        //TODO: check that iss matches subject in cert

        JWSVerifier verifier = new RSASSAVerifier(rsaPubKey);

        boolean signatureValid = signedJWT.verify(verifier);
        if (!signatureValid) {
            throw new VerificationException("JWT signature verification failed");
        }

        JWTClaimsSet signedClaims = signedJWT.getJWTClaimsSet();
        Map<String, Object> signedClaimsMap = signedClaims.getClaims();

        if( Instant.now().isAfter(signedClaims.getExpirationTime().toInstant()) ) {
            throw new VerificationException("JWT is expired " + signedClaims.getExpirationTime());
        }

        if (Instant.now().isBefore(signedClaims.getIssueTime().toInstant())) {
            throw new VerificationException("JWT is from future " + signedClaims.getIssueTime());
        }

        if (tokens_log.isDebugEnabled()) {
            tokens_log.debug("Claims: {}", signedClaimsMap);
            tokens_log.debug("Disclosures: {}", sdJwt.getDisclosures().stream().map(d-> d.digest() +": "+d.getJson()).toList());
        }

        //sdJwt.getDisclosures().stream()
        //    .forEach(d -> log.debug("Parsed disclosure: {} {}",d.digest(), d.getJson()));

        List<Disclosure> disclosures = sdJwt.getDisclosures();

        if (disclosures.size() != 2) {
            throw new VerificationException("Expected exactly 2 disclosures, found " + disclosures.size());
        }

        // disclosure[0]:
        // ["vmD-nMTeXM1yGgtQAlCjVQ","shareAccessData",[{"...":"xJA4uQOVx7Vsa8nAwYSQp3gLCFdT0PAWcPxAkjuJMRI"},
        // {"...":"kD_E_KgMp6CoFdwE1oR-GUf9cq5xEHrXLGBclEjmtKU"}]]

        // disclosure[1] has similar data:
        // ["Zg6oVU7JT5ls3rNwoUzsNg",{"serverNonce":"59b314d4815f21f73a0b9168cecbd5773cc694b6",
        // "serverBaseURL":"https://cdoc-ccs.ria.ee:443/key-shares/","shareId":"9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3"}]
        // claimValue is last object in array
        Object shareAccessDataUnverifiedClaimValue = disclosures.get(1).getClaimValue();

        //log.debug("claimValue: {}", shareAccessDataUnverifiedClaimValue);

        var encodedList = List.of(shareDataClaimtoMap(shareAccessDataUnverifiedClaimValue));

        // check that digests match
        SDObjectDecoder decoder = new SDObjectDecoder();
        List<Object> verifiedClaimValue = decoder.decode(encodedList, disclosures);
        //log.debug("decoded: {}", verified);

        if (verifiedClaimValue.size() != 1) {
            throw new VerificationException("Disclosure not signed/found");
        }

        Map<String, Object> verifiedShareAccessData = shareDataClaimtoMap(verifiedClaimValue.get(0));

        //signedClaimsMap is unmodifiable
        //make shallow copy
        Map<String, Object> all = new HashMap<>(signedClaimsMap);
        // add "shareAccessData" list
        all.put(Constants.SHARE_ACCESS_DATA, List.of(verifiedShareAccessData));

        // experimental: will change in future
        all.put("sharedAccessDataPOJO", shareDataClaimToObj(verifiedClaimValue.get(0)));
        return Collections.unmodifiableMap(all);
    }


    /**
     * Example disclosure, parsed from sdjwt authToken:
     * <code>
     * {shareId=9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3, serverNonce=59b314d4815f21f73a0b9168cecbd5773cc694b6, serverBaseURL=https://cdoc-ccs.ria.ee:443/key-shares/}
     * </code>
     * @param claimValue claim representing serverAccessData parsed from disclosure
     * @return
     */
    public static ShareAccessData shareDataClaimToObj(Object claimValue) {
        return ShareAccessData.fromMap(shareDataClaimtoMap(claimValue));
    }

    /**
     * Convert shareAccessData disclosure into jsonObject. Disclosure claim is expected to have the following data
     * structure:
     * <pre>
     * {"serverNonce":"59b314d4815f21f73a0b9168cecbd5773cc694b6",
     *  "serverBaseURL":"https://cdoc-ccs.ria.ee:443/key-shares/",
     *  "shareId":"9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3"}
     * </pre>>
     * @param claimValue
     * @return
     */
    public static Map<String, Object> shareDataClaimtoMap(Object claimValue) {
        if (!(claimValue instanceof Map)) {
            throw new IllegalArgumentException("Expected claimValue to be instanceof Map");
        }
        Gson gson = new Gson();
        String json = gson.toJson(claimValue);
        return gson.fromJson(new StringReader(json), new TypeToken<Map<String, Object>>() {}.getType());
    }

}
