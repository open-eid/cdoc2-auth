package ee.cyber.cdoc2.auth;

import ee.cyber.cdoc2.auth.exception.InvalidEtsiSemanticsIdentifierException;
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
        Assertions.assertThrows(InvalidEtsiSemanticsIdentifierException.class, () -> {
            new EtsiIdentifier("etsi/XYZEE-30303039914");
        });
    }

    @Test
    void shoudFailWithNotStartingWithEtsi() {
        Assertions.assertThrows(InvalidEtsiSemanticsIdentifierException.class, () -> {
            new EtsiIdentifier("PNOEE-30303039914");
        });
    }

    @Test
    void shoudFailWithWrongHyphenPos() {
        Assertions.assertThrows(InvalidEtsiSemanticsIdentifierException.class, () -> {
            new EtsiIdentifier("etsi/PNOEUR-30303039914");
        });
    }

    @Test
    void shoudFailForTooShort() {
        Assertions.assertThrows(InvalidEtsiSemanticsIdentifierException.class, () -> {
            new EtsiIdentifier("etsi/PNOEE-");
        });
    }

    @Test
    void shoudFailForInvalidCountryCode() {
        Assertions.assertThrows(InvalidEtsiSemanticsIdentifierException.class, () -> {
            new EtsiIdentifier("etsi/PNOE0-30303039914");
        });
    }
}
