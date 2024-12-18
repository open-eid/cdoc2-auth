package ee.cyber.cdoc2.auth.exception;

/**
 * Used when converting aud url to shareAccessObject failed (RuntimeException to be used from functional)
 */
public class MalformedAuthUrlException extends RuntimeException {
    public MalformedAuthUrlException(String message) {
        super(message);
    }

    public MalformedAuthUrlException(Exception cause) {
        super(cause);
    }


    public MalformedAuthUrlException(String message, Exception cause) {
        super(message, cause);
    }

}
