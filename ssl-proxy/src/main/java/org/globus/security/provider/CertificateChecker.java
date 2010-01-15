package org.globus.security.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

import org.globus.security.Constants;

/**
 * Implementations of this interface will provide some validation logic of certificates.
 *
 * @version ${version}
 * @since 1.0
 */
public interface CertificateChecker {
    /**
     * Validate the certificate.
     *
     * @param cert     The certificate to validate.
     * @param certType The type of certificate to validate.
     * @throws CertPathValidatorException If validation fails.
     */
    void invoke(X509Certificate cert, Constants.CertificateType certType) throws CertPathValidatorException;
}
