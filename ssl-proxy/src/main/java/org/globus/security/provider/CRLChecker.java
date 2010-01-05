package org.globus.security.provider;

import org.globus.security.Constants;
import org.globus.security.util.KeyStoreUtil;

import javax.security.auth.x500.X500Principal;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 12:24:13 PM
 * To change this template use File | Settings | File Templates.
 */
public class CRLChecker implements CertificateChecker {
    private CertStore certStore;
    private KeyStore keyStore;
    private boolean checkDateValidity;

    public CRLChecker(CertStore certStore, KeyStore keyStore, boolean checkDateValidity) {
        this.certStore = certStore;
        this.keyStore = keyStore;
        this.checkDateValidity = checkDateValidity;
    }

    /**
     * Method that checks the if the certificate is in a CRL, if CRL is
     * available If no CRL is found, then no error is thrown If an expired CRL
     * is found, an error is thrown
     *
     * @throws CertPathValidatorException If CRL or CA certificate could not be
     *                                    loaded from store, CRL is not valid or
     *                                    expired, certificate is revoked.
     */
    public void invoke(X509Certificate cert, Constants.CertificateType certType) throws CertPathValidatorException {
        X500Principal certIssuer = cert.getIssuerX500Principal();

        X509CRLSelector crlSelector = new X509CRLSelector();
        crlSelector.addIssuer(certIssuer);

        Collection<? extends CRL> crls;
        try {
            crls = this.certStore.getCRLs(crlSelector);
        } catch (CertStoreException e) {
            throw new CertPathValidatorException(
                    "Error accessing CRL from certificate store", e);
        }

        if (crls.size() < 1) {
            return;
        }

        // Get CA certificate for these CRLs
        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setSubject(certIssuer);
        Collection<? extends Certificate> caCerts;
        try {
            caCerts = KeyStoreUtil
                    .getTrustedCertificates(this.keyStore, certSelector);
        } catch (KeyStoreException e) {
            throw new CertPathValidatorException(
                    "Error accessing CA certificate from certificate store for CRL validation",
                    e);
        }

        if (caCerts.size() < 1) {

            // if there is no trusted certs from that CA, then
            // the chain cannot contain a cert from that CA,
            // which implies not checking this CRL should be fine.
            return;
        }
        Certificate caCert = caCerts.iterator().next();

        for (CRL o : crls) {

            X509CRL crl = (X509CRL) o;

            // if expired, will throw error.
            if (checkDateValidity) {
                checkCRLDateValidity(crl);
            }

            // validate CRL
            try {
                crl.verify(caCert.getPublicKey());
            } catch (CRLException e) {
                throw new CertPathValidatorException(
                        "Error validating CRL from CA " + crl.getIssuerDN(), e);
            } catch (NoSuchAlgorithmException e) {
                throw new CertPathValidatorException(
                        "Error validating CRL from CA " + crl.getIssuerDN(), e);
            } catch (InvalidKeyException e) {
                throw new CertPathValidatorException(
                        "Error validating CRL from CA " + crl.getIssuerDN(), e);
            } catch (NoSuchProviderException e) {
                throw new CertPathValidatorException(
                        "Error validating CRL from CA " + crl.getIssuerDN(), e);
            } catch (SignatureException e) {
                throw new CertPathValidatorException(
                        "Error validating CRL from CA " + crl.getIssuerDN(), e);
            }

            if (crl.isRevoked(cert)) {
                throw new CertPathValidatorException(
                        "Certificate " + cert.getSubjectDN() + " has been revoked");

            }
        }
    }

    /**
     * Method to check the CRL validaity for current time.
     *
     * @param crl
     * @throws CertPathValidatorException
     */
    protected void checkCRLDateValidity(X509CRL crl)
            throws CertPathValidatorException {

        Date now = new Date();
        boolean valid = (crl.getThisUpdate().before(now) &&
                ((crl.getNextUpdate() != null) &&
                        (crl.getNextUpdate().after(now))));
        if (!valid) {
            throw new CertPathValidatorException(
                    "CRL issued by " + crl.getIssuerDN() + " has expired");
        }
    }

}
