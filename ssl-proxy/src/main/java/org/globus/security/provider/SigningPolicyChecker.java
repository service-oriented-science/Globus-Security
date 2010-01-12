package org.globus.security.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStoreException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.globus.security.Constants;
import org.globus.security.SigningPolicy;
import org.globus.security.SigningPolicyStore;
import org.globus.security.util.ProxyCertificateUtil;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 12:41:56 PM
 * To change this template use File | Settings | File Templates.
 */
public class SigningPolicyChecker implements CertificateChecker {
    private SigningPolicyStore policyStore;

    public SigningPolicyChecker(SigningPolicyStore policyStore) {
        this.policyStore = policyStore;
    }

    /**
     * Validate DN against the signing policy
     *
     * @param cert
     * @throws CertPathValidatorException
     */
    public void invoke(X509Certificate cert, Constants.CertificateType certType) throws CertPathValidatorException {
        if (!requireSigningPolicyCheck(certType)) {
            return;
        }
        X500Principal caPrincipal = cert.getIssuerX500Principal();
        SigningPolicy policy;
        try {
            policy = this.policyStore.getSigningPolicy(caPrincipal);
        } catch (CertStoreException e) {
            throw new CertPathValidatorException(e);
        }

        if (policy == null) {
            throw new CertPathValidatorException(
                "No signing policy for " + cert.getIssuerDN());
        }

        boolean valid =
            policy.isValidSubject(cert.getSubjectX500Principal());

        if (!valid) {
            throw new CertPathValidatorException(
                "Certificate " + cert.getSubjectDN()
                    + " violates signing policy for CA " + caPrincipal.getName());
        }
    }

    /**
     * if a certificate is not a CA or if it is not a proxy, return true.
     *
     * @param certType The type of Certificate being queried.
     * @return True if the CertificateType requires a Signing Policy check.
     */
    private boolean requireSigningPolicyCheck(
        Constants.CertificateType certType) {

        return !ProxyCertificateUtil.isProxy(certType)
            && certType != Constants.CertificateType.CA;
    }
}
