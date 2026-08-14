package ee.cyber.cdoc2.auth.exception;

/**
 * Signal that Etsi Semantics Identifier is not in expected format.
 */
public class InvalidEtsiSemanticsIdentifierException extends IllegalArgumentException {
    public InvalidEtsiSemanticsIdentifierException(String message) {
        super(message);
    }
}
