package org.globus.security.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.globus.security.Constants;
import org.globus.security.proxyExtension.ProxyCertInfo;
import org.globus.security.util.ProxyCertificateUtil;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 12:08:28 PM
 * To change this template use File | Settings | File Templates.
 */
public class UnsupportedCriticalExtensionChecker implements CertificateChecker {
    /**
     * Method that checks if there are unsupported critical extension. Supported
     * ones are only BasicConstrains, KeyUsage, Proxy Certificate (old and new)
     *
     * @throws CertPathValidatorException If any critical extension that is not
     *                                    supported is in the certificate.
     *                                    Anything other than those listed above
     *                                    will trigger the exception.
     */

    public void invoke(X509Certificate cert, Constants.CertificateType certType) throws CertPathValidatorException {
        Set<String> criticalExtensionOids =
            cert.getCriticalExtensionOIDs();
        if (criticalExtensionOids == null) {
            return;
        }
        for (String criticalExtensionOid : criticalExtensionOids) {
            if (!criticalExtensionOid.equals(X509ProxyCertPathValidator.BASIC_CONSTRAINT_OID)
                && !criticalExtensionOid.equals(X509ProxyCertPathValidator.KEY_USAGE_OID)
                && (!criticalExtensionOid.equals(ProxyCertInfo.OID.toString())
                || !ProxyCertificateUtil.isGsi4Proxy(certType))
                && (!criticalExtensionOid.equals(ProxyCertInfo.OLD_OID.toString())
                || !ProxyCertificateUtil.isGsi3Proxy(certType))) {
                throw new CertPathValidatorException("Critical extension with unsupported OID " + criticalExtensionOid);
            }
        }
    }
}
