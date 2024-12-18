package ee.cyber.cdoc2.auth;

import ee.cyber.cdoc2.auth.exception.VerificationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertVerifierTest {
    @Test
    void shouldVerify() throws Exception {
        CertVerifier verifier = new CertVerifier(TestData.createTestIssuerTrustStore(), false);
        assertNotNull(verifier);

        // no exception means success
        verifier.checkCertificate(TestData.loadTestCert());
    }

    @Test
    void shouldNotVerifyWhenRevocationAreEnabled() throws Exception {

        CertVerifier verifier = new CertVerifier(TestData.createTestIssuerTrustStore(), true);

        // TEST_CERT doesn't have AIA extension, should fail
        VerificationException ex = Assertions.assertThrows(VerificationException.class, () ->
            verifier.checkCertificate(TestData.loadTestCert())
        );
    }

    @Test
    void shouldNotVerifyWhenTrustStoreDoesNotContainIssuer() throws Exception {

        X509Certificate cert = TestData.loadTestCert();
        KeyStore selfTustStore = TestData.createEmptyTrustStore();

        // truststore cannot be empty, add test cert
        selfTustStore.setCertificateEntry(cert.getSubjectX500Principal().getName(), cert);

        CertVerifier verifier = new CertVerifier(selfTustStore, false);

        // TEST_CERT is not self-signed, should fail
        VerificationException ex = Assertions.assertThrows(VerificationException.class, () ->
            verifier.checkCertificate(TestData.loadTestCert())
        );

        assertTrue(ex.getCause() instanceof CertPathValidatorException);
    }
}
