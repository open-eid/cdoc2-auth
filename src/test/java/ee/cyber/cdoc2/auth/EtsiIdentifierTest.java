package ee.cyber.cdoc2.auth;

import ee.cyber.cdoc2.auth.exception.InvalidEtsiSemanticsIdenfierException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EtsiIdentifierTest {

    @Test
    void shouldParseSuccessfully() {
        String etsiStr = "etsi/PNOEE-30303039914";

        EtsiIdentifier etsi = new EtsiIdentifier(etsiStr);

        assertEquals("EE", etsi.getCountryCode());
        assertEquals("30303039914", etsi.getIdentifier());
        assertEquals("PNOEE-30303039914", etsi.getSemanticsIdentifier());
        assertTrue(EtsiIdentifier.IdentityType.PNO == etsi.getIdentityType());
    }

    @Test
    void shoudFailWithInvalidIdentityType() {
        Assertions.assertThrows(InvalidEtsiSemanticsIdenfierException.class, () -> {
            new EtsiIdentifier("etsi/XYZEE-30303039914");
        });
    }

    @Test
    void shoudFailWithNotStartingWithEtsi() {
        Assertions.assertThrows(InvalidEtsiSemanticsIdenfierException.class, () -> {
            new EtsiIdentifier("PNOEE-30303039914");
        });
    }

    @Test
    void shoudFailWithWrongHyphenPos() {
        Assertions.assertThrows(InvalidEtsiSemanticsIdenfierException.class, () -> {
            new EtsiIdentifier("PNOEUR-30303039914");
        });
    }

    @Test
    void shoudFailForTooShort() {
        Assertions.assertThrows(InvalidEtsiSemanticsIdenfierException.class, () -> {
            new EtsiIdentifier("PNOEE-");
        });
    }

    @Test
    void shoudFailForInvalidCountryCode() {
        Assertions.assertThrows(InvalidEtsiSemanticsIdenfierException.class, () -> {
            new EtsiIdentifier("PNOE0-30303039914");
        });
    }


}
