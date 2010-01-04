package org.globus.security.provider;

import org.globus.security.Constants;
import org.globus.security.util.ProxyCertificateUtil;

import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 12:15:43 PM
 * To change this template use File | Settings | File Templates.
 */
public class IdentityChecker implements CertificateChecker {
    private X509ProxyCertPathValidator proxyCertValidator;

    public IdentityChecker(X509ProxyCertPathValidator proxyCertPathValidator) {
        this.proxyCertValidator = proxyCertPathValidator;
    }


    /**
     * Method that sets the identity of the certificate path. Also checks if
     * limited proxy is acceptable.
     *
     * @throws CertPathValidatorException If limited proxies are not accepted
     *                                    and the chain has a limited proxy.
     */

    public void invoke(X509Certificate cert, Constants.CertificateType certType) throws CertPathValidatorException {
        if (proxyCertValidator.getIdentityCertificate() == null) {
            // check if limited
            if (ProxyCertificateUtil.isLimitedProxy(certType)) {
                proxyCertValidator.setLimited(true);

                if (proxyCertValidator.rejectLimitedProxy) {
                    throw new CertPathValidatorException(
                            "Limited proxy not accepted");
                }
            }

            // set the identity cert
            if (!ProxyCertificateUtil.isImpersonationProxy(certType)) {
                proxyCertValidator.setIdentityCertificate(cert);
            }
        }
    }
}
