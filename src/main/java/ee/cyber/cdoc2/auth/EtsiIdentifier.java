package ee.cyber.cdoc2.auth;

public class EtsiIdentifier {

    private final String etsi;
    /**
     * @param etsi etsi semantic identifier, for example "etsi/PNOEE-48010010101"
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
