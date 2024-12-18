package ee.cyber.cdoc2.auth.exception;

/**
 * Signal that Etsi Semantics Identifier is not in expected format.
 */
public class InvalidEtsiSemanticsIdenfierException extends IllegalArgumentException {
    public InvalidEtsiSemanticsIdenfierException(String message) {
        super(message);
    }
}
