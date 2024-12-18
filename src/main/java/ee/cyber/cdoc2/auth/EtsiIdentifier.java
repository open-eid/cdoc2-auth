package ee.cyber.cdoc2.auth;

import ee.cyber.cdoc2.auth.exception.InvalidEtsiSemanticsIdenfierException;

import java.util.Objects;

/**
 * Natural person semantics identifier from ETSI319412-1, example "etsi/PNOEE-48010010101"
 * @see <a href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.04.02_20/en_31941201v010402a.pdf">ETSI319412-1</a>
 */
public class EtsiIdentifier {

    private static final int MIN_LEN = "etsi/PNOEE-0".length();
    private static final int HYPHEN_POS = "etsi/PNOEE-0".indexOf("-");

    private static final int IDENTITY_TYPE_START = "etsi/".length();
    private static final int IDENTITY_TYPE_END = IDENTITY_TYPE_START + "PNO".length();

    private static final int COUNTRY_CODE_START = "etsi/PNO".length();
    private static final int COUNTRY_CODE_END = COUNTRY_CODE_START + "EE".length();

    private static final int IDENTIFIER_START = "etsi/PNOEE-".length();

    private final String etsiSemanticsIdentifier;

    // fields parsed from etsiSemanticsIdentifier
    private final IdentityType identityType;
    private final String countryCode;
    private final String identifier;
    /**
     * Etsi Semantics Identifier. Format "etsi/:semantics-identifier" as in ETSI319412 - 1
     * @param etsi etsi semantic identifier, for example "etsi/PNOEE-48010010101"
     * @throws InvalidEtsiSemanticsIdenfierException when etsi is not in expected format
     * @see <a href="https://github.com/SK-EID/smart-id-documentation?tab=readme-ov-file#2322-etsisemantics-identifier">
     *     Etsi Semantics Identifier
     *     </a>
     */
    public EtsiIdentifier(String etsi) throws InvalidEtsiSemanticsIdenfierException {
        validateEtsiSemanticsIdentifier(etsi);
        this.etsiSemanticsIdentifier = etsi;

        this.identityType = parseIdentityType(etsi);
        this.countryCode = parseCountryCode(etsi);
        this.identifier = parseIdentifier(etsi);
    }

    public String getIdentifier() { return this.identifier; }

    public String getCountryCode() { return this.countryCode; }

    public IdentityType getIdentityType() { return this.identityType; }

    public String getSemanticsIdentifier() {
        return this.etsiSemanticsIdentifier.substring(IDENTITY_TYPE_START);
    }

    private void validateEtsiSemanticsIdentifier(String etsi) throws InvalidEtsiSemanticsIdenfierException {
        Objects.requireNonNull(etsi);

        if (!etsi.startsWith("etsi/")) {
            throw new InvalidEtsiSemanticsIdenfierException(etsi + "doesn't start with etsi/");
        }

        if (etsi.length() < MIN_LEN) {
            throw new InvalidEtsiSemanticsIdenfierException(etsi + " is too short");
        }

        if (etsi.charAt(HYPHEN_POS) != '-') {
            throw new InvalidEtsiSemanticsIdenfierException("- not found in expected position for " + etsi);
        }
    }

    private IdentityType parseIdentityType(String etsi) throws InvalidEtsiSemanticsIdenfierException {
        String type = etsi.substring(IDENTITY_TYPE_START, IDENTITY_TYPE_END);

        try {
            return IdentityType.valueOf(type);
        } catch (IllegalArgumentException e) {
            throw new InvalidEtsiSemanticsIdenfierException("Unknown identity type \"" + type + "\"");
        }
    }

    /**
     * Parse ISO 3166-1 alpha-2 two-letter country code from etsi
     * @param etsi etsi semantic identifier, for example "etsi/PNOEE-48010010101"
     * @return two-letter country code
     */
    private String parseCountryCode(String etsi) {
        String cc =  etsi.substring(COUNTRY_CODE_START, COUNTRY_CODE_END);
        if (!cc.matches("[A-Z]+")){
            throw new InvalidEtsiSemanticsIdenfierException("Country code \""
                + cc + "\" should contain only uppercase characters ");
        }
        return cc;
    }

    /**
     * Parse identifier from etsi semantic identifier. Return "48010010101" from "etsi/PNOEE-48010010101"
     * @param etsi etsi semantic identifier, for example "etsi/PNOEE-48010010101"
     * @return identifier
     */
    private String parseIdentifier(String etsi) {
        return etsi.substring(IDENTIFIER_START);
    }

    /**
     * Return full etsi semantics identifier "etsi/:semantics-identifier", for example "etsi/PNOEE-48010010101"
     * @return full etsi semantics identifier
     */
    public String toString() {
        return this.etsiSemanticsIdentifier;
    }

    public enum IdentityType {
        /** for identification based on passport number */
        PAS,
        /** for identification based on national identity card number */
        IDC,
        /** for identification based on (national) personal number (national civic registration number) */
        PNO
    }
}
