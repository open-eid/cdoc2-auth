package ee.cyber.cdoc2.auth;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * cdoc2 auth ticket is used to authenticate against multiple key-share servers by signing authenticated data ones and
 * not revealing auth data to other servers. For this SDJWT is usde
 * Create SDJWT in format:
 * <pre>
 *  &lt;JWT_header&gt;.&lt;JWT_payload&gt;.&lt;JWT_signature&gt;~&lt;SD_SaltAndValueContainer&gt;~&lt;SD_share_claim&gt;~
 *</pre>
 *
 * Ticket will be SDJWT, where:
 * JWT_header:
 * <pre>
 * {
 *   "typ": "vnd.cdoc2.CTS-auth-token.v1+sd-jwt",
 *   "alg": "PS256",
 *   "jwk": {
 *     "kty": "RSA",
 *     "e": "AQAB",
 *     "n": "4y...ms"
 *   }
 * }
 * </pre>
 * JWT_payload:
 * <pre>
 *     {
 *   "iss": "etsi/PNOEE-48010010101",
 *   "serverAccessData": [
 *     {
 *          "serverBaseURL": "https://cdoc-ccs.ria.ee:443/key-shares/",
 *          "shareId": "9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3",
 *          "serverNonce": "59b314d4815f21f73a0b9168cecbd5773cc694b6"},
 *     {
 *        "serverBaseURL": "https://cdoc-ccs.smit.ee:443/key-shares/",
 *        "serverNonce: "5BAE4603-C33C-4425-B301-125F2ACF9B1E",
 *        "shareId": "9d23660840b427f405009d970d269770417bc769"
 *     }
 *   ],
 *   "exp": 1728651637,
 *   "iat": 1728651577,
 * * }
 * </pre>
 *
 * JWT_signature is standard JWT signature, signed with private key of jwk from header.
 * <p>
 * "serverAccessData" array will be made selectively disclosable recursively
 * (https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-12.html#section-5.2.6), so that signed
 * data (payload) in JWT is something like:
 * <p>
 * <code>
 * {
 *   "iss": "etsi/PNOEE-48010010101",
 *   "_sd": ["6s6qz3P2kc-2kYa_hwX5HKMRFVHHZd96X-hC4g4T_U0"],
 *   "_sd_alg": "sha-256",
 *   "exp": 1728651637,
 *   "iat": 1728651577,
 *  }
 * </code>
 * <p>
 * SD_SaltAndValueContainer (disclosure1 base64urldecode data between first ~ and second ~):
 * 6s6qz3P2kc-2kYa_hwX5HKMRFVHHZd96X-hC4g4T_U0:
 * <pre>
 * ["ptzUMtwdfdUZAouwfkRG_w","shareAccessData",[{"...":"gWMKAStqzQ6j_sBqhSc8YzTcULduxK9Xlg6ISc2mXEA"},{"...":"xOJU66mAin0dB-aa34bv_GrsjQRL-QOA_5OooO5HGYg"}]
 * </pre>
 *
 * SD_share_claim (disclosed data for single share):
 * gWMKAStqzQ6j_sBqhSc8YzTcULduxK9Xlg6ISc2mXEA:
 *  <pre>
 * ["eIk0a2LvzANGIQwIZTvrZQ",{"serverNonce":"59b314d4815f21f73a0b9168cecbd5773cc694b6","shareId":"9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3","serverBaseURL":"https://cdoc-ccs.ria.ee:443/key-shares/"}]
 * </pre>
 *
 * After signatures and hashes were validated, then following structure is returned by (jsonObject)
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
 * </code>
 */
public class AuthTokenCreator {
    private static final Logger log = LoggerFactory.getLogger(AuthTokenCreator.class);

    private static final Logger tokens_log = LoggerFactory.getLogger("tokens");

    private final EtsiIdentifier signerEtsiIdentifier;
    private final Duration expAfterDuration;
    private final ShareAccessData[] shareAccessData;

    private final List<Disclosure> shareAccessDisclosureArray;

    private final Disclosure disclosedShareAccessData;

    private SignedJWT signedJWT = null; // initialized by sign()

    private AuthTokenCreator(EtsiIdentifier signer, ShareAccessData[] sharesData, Duration expAfterDuration) {
        this.signerEtsiIdentifier = signer;
        this.shareAccessData = sharesData;
        this.expAfterDuration = (expAfterDuration == null) ? Duration.ofSeconds(60): expAfterDuration;

        this.shareAccessDisclosureArray = initDisclosureArray();  //generate salts
        this.disclosedShareAccessData = genDisclosedShareAccessData(); //generate salt
    }

    /**
     * Create shareAccessData claim where value is array of ["generated_salt", {}]
     */
    private List<Disclosure> initDisclosureArray() {
        return Arrays.stream(shareAccessData)
            .map(claimValue ->
                new Disclosure(claimValue.toMap()) // generated salt, claimValue
            )
            .toList();
    }

    /**
     * Creates array of disclosure digests from keyShareAccessData
     * Json representation of "shareAccessData" disclosures (formatted for readability):
     * <code>
     * [
     *     "k-4EaZpAg-17QnMfOwMbOw",
     *     "shareAccessData",
     *     [
     *         {
     *             "...": "EEs_5efYCyYSch0ze2JgUlWEiIXsq6bsZ8QqAvyjeuM"
     *         },
     *         {
     *             "...": "F_-6nsDCOCoJcNKfa87VgAMTTs87KF3zYysmJgC1wrE"
     *         }
     *     ]
     * ]
     * </code>
     * Digest EEs_5efYCyYSch0ze2JgUlWEiIXsq6bsZ8QqAvyjeuM is calculated from following input:
     * <code>
     * echo -n '["LQ3tyLN4vUl4EjDtzGfEQg", {"serverBaseURL": "https://cdoc-ccs.ria.ee:443/key-shares/", "shareId": "9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3", "serverNonce": "42"}]' \
     * |base64url|tr -d '=\n'|openssl dgst -sha256 -binary|base64url|tr -d '=\n'
     * </code>
     * @return
     */
    private Disclosure genDisclosedShareAccessData() {
        return new Disclosure("shareAccessData",
            shareAccessDisclosureArray.stream()
                .map(Disclosure::toArrayElement
            ).toList()
        );
    }

    private Disclosure getDisclosedShareAccessData() {
        return this.disclosedShareAccessData;
    }

    /**
     * Create payload for JWT
     * <code>
     *     {"iss":"etsi/PNOEE-48010010101","_sd":["1STjFlBH6jmF270Ify2StXnMzZ2TDrIKJX5By65gv-4"],"exp":1728552239,"iat":1728552179,"_sd_alg":"sha-256"}
     * </code>
     * Digest 1STjFlBH6jmF270Ify2StXnMzZ2TDrIKJX5By65gv-4 was calculated from following input:
     * <code>
     * ["k-4EaZpAg-17QnMfOwMbOw", "shareAccessData", [{"...": "EEs_5efYCyYSch0ze2JgUlWEiIXsq6bsZ8QqAvyjeuM"}, {"...": "F_-6nsDCOCoJcNKfa87VgAMTTs87KF3zYysmJgC1wrE"}]]
     * </code>
     *
     * @return
     * @throws ParseException
     */
    private JWTClaimsSet createPayload() throws ParseException {
        // Create an SDObjectBuilder instance to prepare the payload part of
        // a credential JWT. "sha-256" is used as a hash algorithm to compute
        // digest values of Disclosures.
        SDObjectBuilder builder = new SDObjectBuilder();

        // Put the digest value of the Disclosure.
        // will create claim  "_sd": ["y7ePxU9QuqYLz8ITcxcDAA4T43VDzF9_x2Z3z0-xxls"] that is calculated from
        // disclosed sharedAccessData array, see getDisclosedShareAccessData()
        builder.putSDClaim(getDisclosedShareAccessData());

        // instead selectively disclosed shareAccessData that is recursively disclosed, could use standard "aud"
        // "aud": ["https://cdoc-ccs.ria.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3/nonce/59b314d4815f21f73a0b9168cecbd5773cc694b6",
        // "https://cdoc-ccs.smit.ee:443/key-shares/5BAE4603-C33C-4425-B301-125F2ACF9B1E/nonce/9d23660840b427f405009d970d269770417bc769"]
        // and then disclose its array elements (without recursion)
        // "aud": [{"...": "PmnlrRjhLcwf8zTDdK15HVGwHtPYjddvD362WjBLwro"},{"...":"r823HFN6Ba_lpSANYtXqqCBAH-TsQlIzfOK0lRAFLCM"}]
        // most libs restore disclosed data after verifying. It would make sdjwt "more standard" and shorter

        // Create a Map instance that represents the payload part of a
        // credential JWT. The 'claims' map contains the "_sd" array.
        // The size of the array is 1.
        Map<String, Object> claims = builder.build(true);

        JWTClaimsSet regularClaims = new JWTClaimsSet.Builder()
            .issueTime(new Date()) //iat
            .expirationTime(Date.from(Instant.now().plusMillis(expAfterDuration.toMillis()))) //exp
            .issuer(signerEtsiIdentifier.toString())//iss
            .build();

        claims.putAll(regularClaims.toJSONObject());

        // Prepare the payload part of a credential JWT.
        return JWTClaimsSet.parse(claims);
    }

    /**
     * Create payload part of JWT and sign it with JWSSigner and JWK private key. (Currently only RSAsigner and matching RSA public jwk is supported)
     * @param signer jwsSigner, currently only RSASigner is supported
     * @param keyID key id that identifies the signer. For now in format "PNOEE-30303039914"
     * @throws JOSEException
     * @throws ParseException
     */
    //Currently only RSASigner and RSA public jwk are supported
    public void sign(JWSSigner signer, String keyID) throws JOSEException, ParseException {
        //for SID certificate is available after successful authentication (that is actually signing with different key - PIN1)
        //for now use jwk (RSA)

        JWSHeader header =
            new JWSHeader.Builder(JWSAlgorithm.RS256) //RSASSA-PKCS1.5, according SID RP API doc, only signature padding that is supported
                .type(new JOSEObjectType(Constants.TYPE))
                .keyID(keyID)
                .build();

        //log.debug("jwt_header: {}", header.toJSONObject());

        // Create a credential JWT. (not signed yet)
        SignedJWT jwt = new SignedJWT(header, createPayload());

        // Let the signer sign the credential JWT.
        jwt.sign(signer); //signer requires header, but header seems to be only required for JWSAlgorithm

        //log.debug("Signed JWT: {}", jwt.serialize());
        this.signedJWT = jwt;
    }

    /**
     * Create ticket (sdjwt)
     * @param index shareAccessData element index from signed shareAccessData
     * @return ticket as SDJWT
     */
    public String createTicket(int index) {
        if (this.signedJWT == null) {
            throw new IllegalStateException("jwt not signed, can't create ticket (did you call sign()?)");
        }

        if ((index < 0) || (index > shareAccessDisclosureArray.size())) {
            throw new IllegalArgumentException("Invalid index "+index);
        }

        SDJWT sdjwt = new SDJWT(this.signedJWT.serialize(),
            List.of(getDisclosedShareAccessData(), shareAccessDisclosureArray.get(index)));

        if (tokens_log.isDebugEnabled()) {
            try {
                tokens_log.debug("Claims: {}", signedJWT.getJWTClaimsSet());
            } catch (ParseException e) {
                throw new IllegalStateException("Should not happen as jwt is not parsed");
            }
            tokens_log.debug("Disclosures: {}", sdjwt.getDisclosures().stream().map(d-> d.digest() +": "+d.getJson()).toList());
        }

        return sdjwt.toString();
    }

    /**
     * Create ticket (sdjwt) for share id
     * @param shareId shareId from signed shareAccessData
     * @return ticket as SDJWT
     * @throws IllegalArgumentException if shareId was not part signed payload
     */
    public String createTicketForShareId(String shareId) {
        Objects.requireNonNull(shareId);

        for (int i=0; i < shareAccessData.length; i++) {
            if (shareId.equals(shareAccessData[i].getShareId())) {
                return createTicket(i);
            }
        }

        throw new IllegalArgumentException(shareId + "not found");
    }

    public static class Builder {
        EtsiIdentifier etsiIdentifier;
        Collection<ShareAccessData> keyShares = new LinkedList<>();
        Duration duration;

        public Builder withEtsiIdentifier(EtsiIdentifier identifier) {
            this.etsiIdentifier = identifier;
            return this;
        }

        /**
         * Add share access data
         * @param share to add to data to be signed
         * @return
         */
        public Builder withShareAccessData(ShareAccessData share){
            this.keyShares.add(share);
            return this;
        }

        /**
         * Add shares access data
         * @param shares to add to data to be signed
         * @return
         */
        public Builder withSharesAccessData(List<ShareAccessData> shares) {
            this.keyShares.addAll(shares);
            return this;
        }

        public Builder withExpiration(Duration duration) {
            this.duration = duration;
            return this;
        }

//        public Builder withSigner(JWSSigner jwsSigner) {
//            return this;
//        }

        public AuthTokenCreator build() {
            return new AuthTokenCreator(this.etsiIdentifier, keyShares.toArray(new ShareAccessData[0]), duration);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
