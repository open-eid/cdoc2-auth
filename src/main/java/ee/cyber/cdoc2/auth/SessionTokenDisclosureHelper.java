package ee.cyber.cdoc2.auth;

import java.util.List;
import java.util.Optional;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;

public final class SessionTokenDisclosureHelper {

    private SessionTokenDisclosureHelper() {
        // utility class
    }

    /**
     * Transforms an SD-JWT with an obfuscated 'aud' claim and 1..n aud array element disclosures
     * into and SD-JWT with and 'aud' disclosure and one aud array element disclosure, filtering
     * aud array element disclosures by claimValue
     *
     * @param sessionTokenBase64Url SD-JWT
     * @param claimValue            value used to filter aud array element disclosures
     * @return Base64Url encoded SD-JWT
     */
    public static String discloseAudByClaimValue(String sessionTokenBase64Url, String claimValue) {
        SDJWT sdjwt = SDJWT.parse(sessionTokenBase64Url);

        List<Disclosure> disclosures = sdjwt.getDisclosures();

        Optional<Disclosure> audDisclosure = disclosures.stream()
            .filter(disclosure -> "aud".equals(disclosure.getClaimName()))
            .findFirst();

        List<Disclosure> toDisclose = disclosures.stream()
            .filter(disclosure ->
                disclosure.getClaimName() == null
                    && disclosure.getClaimValue().toString().contains(claimValue))
            .toList();

        if (audDisclosure.isEmpty() || toDisclose.size() != 1) {
            return null;
        }

        SDJWT sdJwtWithFilteredDisclosures = new SDJWT(sdjwt.getCredentialJwt(), List.of(
            audDisclosure.get(),
            toDisclose.get(0)
        ));

        return sdJwtWithFilteredDisclosures.toString();
    }
}
