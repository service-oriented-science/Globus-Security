package org.globus.security.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import org.globus.security.Constants;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 11:55:36 AM
 * To change this template use File | Settings | File Templates.
 */
public class DateValidityChecker implements CertificateChecker {

    /**
     * Method that checks the time validity. Uses the standard
     * Certificate.checkValidity method.
     *
     * @throws CertPathValidatorException If certificate has expired or is not
     *                                    yet valid.
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
