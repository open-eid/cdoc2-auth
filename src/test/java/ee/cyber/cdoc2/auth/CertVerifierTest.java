package ee.cyber.cdoc2.auth;

import ee.cyber.cdoc2.auth.exception.VerificationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.List;

import static ee.cyber.cdoc2.auth.TestData.SID_PUBLIC_KEY_ALGORITHM;
import static ee.cyber.cdoc2.auth.TestData.TEST_PEM_30303039914;
import static ee.cyber.cdoc2.auth.TestData.TEST_30303039914_ISSUER_PEM;
import static ee.cyber.cdoc2.auth.TestData.TEST_30303039914_ISSUER_ROOT_PEM;
import static ee.cyber.cdoc2.auth.TestData.TEST_RSA_CERT_ISSUER_PEM;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CertVerifierTest {

    @Test
    void shouldVerify() throws Exception {
        CertVerifier verifier = new CertVerifier(
            TestData.createTestIssuerTrustStore(
                List.of(TEST_RSA_CERT_ISSUER_PEM)), false
        );
        assertNotNull(verifier);

        // no exception means success
        verifier.checkCertificate(TestData.loadDefaultTestCert(SID_PUBLIC_KEY_ALGORITHM));
    }

    @Test
    @Tag("ocsp")
    @Disabled("AIA/OCSP signing certificate is rotated every month, so the CN field will change"
        + "monthly. Update issuer certificate for 30303039914 and run test manually.")
    void shouldVerifyWithCertRevocationCheck() throws Exception {
        CertVerifier verifier = new CertVerifier(
            TestData.createTestIssuerTrustStore(
                List.of(TEST_30303039914_ISSUER_PEM, TEST_30303039914_ISSUER_ROOT_PEM)),
            true
        );
        assertNotNull(verifier);

        // no exception means success
        verifier.checkCertificate(TestData.loadTestCert(TEST_PEM_30303039914));
    }

    @Test
    void shouldNotVerifyWhenRevocationAreEnabled() throws Exception {
        CertVerifier verifier = new CertVerifier(
            TestData.createTestIssuerTrustStore(List.of(TEST_RSA_CERT_ISSUER_PEM)), true
        );

        // TEST_CERT doesn't have AIA extension, should fail
        VerificationException ex = Assertions.assertThrows(VerificationException.class, () ->
            verifier.checkCertificate(TestData.loadDefaultTestCert(SID_PUBLIC_KEY_ALGORITHM))
        );

        assertInstanceOf(CertPathValidatorException.class, ex.getCause());
    }

    @Test
    void shouldNotVerifyWhenTrustStoreDoesNotContainIssuer() throws Exception {
        X509Certificate cert = TestData.loadDefaultTestCert(SID_PUBLIC_KEY_ALGORITHM);
        KeyStore selfTrustStore = TestData.createEmptyTrustStore();

        // truststore cannot be empty, add test cert
        selfTrustStore.setCertificateEntry(cert.getSubjectX500Principal().getName(), cert);

        CertVerifier verifier = new CertVerifier(selfTrustStore, true);

        // TEST_CERT is not self-signed, should fail
        VerificationException ex = Assertions.assertThrows(VerificationException.class, () ->
            verifier.checkCertificate(TestData.loadDefaultTestCert(SID_PUBLIC_KEY_ALGORITHM))
        );

        assertInstanceOf(CertPathValidatorException.class, ex.getCause());
    }
}
