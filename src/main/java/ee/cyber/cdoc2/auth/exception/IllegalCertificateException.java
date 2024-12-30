package ee.cyber.cdoc2.auth.exception;

/**
 * Signals that parsed certificate didn't have expected fields or was otherwise erroneous.
 * (Runtime exception to allow throwing from functional interface)
 */
public class IllegalCertificateException extends RuntimeException {
  public IllegalCertificateException(String message) {
    super(message);
  }
  public IllegalCertificateException(String message, Throwable t) {
    super(message, t);
  }
}
