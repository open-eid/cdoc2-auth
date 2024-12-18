package ee.cyber.cdoc2.auth.exception;

/**
 * Signals that auth ticket verification has failed
 */
public class VerificationException extends Exception {

    public VerificationException(String msg) {
        super(msg);
    }

    public VerificationException(String msg, Throwable ex) {
        super(msg, ex);
    }

}
