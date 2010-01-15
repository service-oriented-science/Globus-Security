package org.globus.security.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import org.globus.security.Constants;

/**
 * Checks if the certificate has expried or is not yet valid.
 *
 * @version ${version}
 * @since 1.0
 */
public class DateValidityChecker implements CertificateChecker {

    /**
     * Method that checks the time validity. Uses the standard Certificate.checkValidity method.
     *
     * @throws CertPathValidatorException If certificate has expired or is not yet valid.
     */

    public void invoke(X509Certificate cert, Constants.CertificateType certType) throws CertPathValidatorException {
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new CertPathValidatorException(
                "Certificate " + cert.getSubjectDN() + " expired", e);
        } catch (CertificateNotYetValidException e) {
            throw new CertPathValidatorException(
                "Certificate " + cert.getSubjectDN() + " not yet valid.", e);
        }
    }
}
