package ee.cyber.cdoc2.auth;

import java.util.List;
import java.util.Optional;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;

public final class SessionTokenHelper {

    private SessionTokenHelper() {
        // utility class
    }

    public static String discloseByClaimValue(String sessionTokenBase64Url, String claimValue) {
        SDJWT sdjwt = SDJWT.parse(sessionTokenBase64Url);

        List<Disclosure> disclosures = sdjwt.getDisclosures();

        Optional<Disclosure> audDisclosure = disclosures.stream()
            .filter(disclosure -> "aud".equals(disclosure.getClaimName()))
            .findFirst();

        Optional<Disclosure> toDisclose = disclosures.stream()
            .filter(disclosure ->
                disclosure.getClaimName() == null
                    && disclosure.getClaimValue().toString().contains(claimValue))
            .findFirst();

        if (audDisclosure.isEmpty() || toDisclose.isEmpty()) {
            return null;
        }

        SDJWT sdJwtWithFilteredDisclosures = new SDJWT(sdjwt.getCredentialJwt(), List.of(
            audDisclosure.get(),
            toDisclose.get()
        ));

        return sdJwtWithFilteredDisclosures.toString();
    }
}
