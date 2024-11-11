package ee.cyber.cdoc2.auth;

public class EtsiIdentifier {

    private final String etsi;

    /**
     * Etsi Semantics Identifier. Format "etsi/:semantics-identifier" as in ETSI319412 - 1
     * @param etsi etsi semantic identifier, for example "etsi/PNOEE-48010010101"
     * @see <a href="https://github.com/SK-EID/smart-id-documentation?tab=readme-ov-file#2322-etsisemantics-identifier">
     *     Etsi Semantics Identifier
     *     </a>
     */
    public EtsiIdentifier(String etsi) {
        this.etsi = etsi; //TODO: validation
    }

    public String toString() {
        return this.etsi;
    }

    public enum IdentityType {
        PAS, IDC, PNO
    }
}
