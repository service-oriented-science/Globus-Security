/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.security.provider;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.globus.security.Constants;
import org.globus.security.SigningPolicy;
import org.globus.security.SigningPolicyStore;
import org.globus.security.X509ProxyCertPathParameters;
import org.globus.security.X509ProxyCertPathValidatorResult;
import org.globus.security.proxyExtension.ProxyCertInfo;
import org.globus.security.proxyExtension.ProxyPolicy;
import org.globus.security.proxyExtension.ProxyPolicyHandler;
import org.globus.security.util.CertificateUtil;
import org.globus.security.util.KeyStoreUtil;
import org.globus.security.util.ProxyCertificateUtil;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Implementation of the CertPathValidatorSpi and the logic for X.509 Proxy Path
 * Validation.
 *
 * @author ranantha@mcs.anl.gov
 */
public class X509ProxyCertPathValidator extends CertPathValidatorSpi {

    public final String BASIC_CONSTRAINT_OID = "2.5.29.19";
    public final String KEY_USAGE_OID = "2.5.29.15";

    private X509Certificate identityCert;
    private boolean limited = false;
    boolean rejectLimitedProxy = false;
    KeyStore keyStore;
    CertStore certStore;
    SigningPolicyStore policyStore;
    Map<String, ProxyPolicyHandler> policyHandlers;

    /**
     * Validates the specified certification path using the specified algorithm
     * parameter set.
     * <p/>
     * The <code>CertPath</code> specified must be of a type that is supported
     * by the validation algorithm, otherwise an <code>InvalidAlgorithmParameterException</code>
     * will be thrown. For example, a <code>CertPathValidator</code> that
     * implements the PKIX algorithm validates <code>CertPath</code> objects of
     * type X.509.
     *
     * @param certPath the <code>CertPath</code> to be validated
     * @param params   the algorithm parameters
     * @return the result of the validation algorithm
     * @throws java.security.cert.CertPathValidatorException
     *          if the <code>CertPath</code> does not validate
     * @throws java.security.InvalidAlgorithmParameterException
     *          if the specified parameters or the type of the specified
     *          <code>CertPath</code> are inappropriate for this
     *          <code>CertPathValidator</code>
     */
    public CertPathValidatorResult engineValidate(CertPath certPath,
                                                  CertPathParameters params)
        throws CertPathValidatorException, InvalidAlgorithmParameterException {

        if (certPath == null) {
            throw new IllegalArgumentException(
                "Certificate path cannot be null");
        }

        List list = certPath.getCertificates();
        if (list.size() < 1) {
            throw new IllegalArgumentException(
                "Certificate path cannot be empty");
        }

        parseParameters(params);

        // find the root trust anchor. Validate signatures and see if the
        // chain ends in one of the trust root certificates
        CertPath trustedCertPath = findTrustedCertPath(certPath);

        // rest of the validation
        return validate(trustedCertPath);
    }

    public void clear() {

        this.identityCert = null;
        this.limited = false;
    }

    protected void parseParameters(CertPathParameters params)
        throws InvalidAlgorithmParameterException {

        if (!(params instanceof X509ProxyCertPathParameters)) {
            throw new IllegalArgumentException("Parameter of type "
                                               +
                                               X509ProxyCertPathParameters.class
                                                   .getName() + " required");
        }

        X509ProxyCertPathParameters parameters =
            (X509ProxyCertPathParameters)params;
        this.keyStore = parameters.getKeyStore();
        this.certStore = parameters.getCertStore();
        this.policyStore = parameters.getSigningPolicyStore();
        this.rejectLimitedProxy = parameters.isRejectLimitedProxy();
        this.policyHandlers = parameters.getPolicyHandlers();
    }

    /**
     * Validates the certificate path and does the following for each
     * certificate in the chain: method checkCertificate() In addition: a)
     * Validates if the issuer type of each certificate is correct b) CA path
     * constraints c) Proxy path constraints
     * <p/>
     * If it is of type proxy, check following: a) proxy constraints b)
     * restricted proxy else if cerificate, check the following: a) key isage
     *
     * @param certPath
     * @throws CertPathValidatorException
     */
    protected CertPathValidatorResult validate(CertPath certPath)
        throws CertPathValidatorException {

        List<? extends Certificate> certificates = certPath.getCertificates();
        if (certificates.isEmpty()) {
            return null;
        }

        X509Certificate cert;
        TBSCertificateStructure tbsCert;
        Constants.CertificateType certType;

        X509Certificate issuerCert;
        TBSCertificateStructure issuerTbsCert;
        Constants.CertificateType issuerCertType;

        int proxyDepth = 0;

        cert = (X509Certificate)certificates.get(0);

        try {
            tbsCert = CertificateUtil.getTBSCertificateStructure(cert);
        } catch (CertificateException e) {
            throw new CertPathValidatorException("Error converting certificate",
                                                 e);
        } catch (IOException e) {
            throw new CertPathValidatorException("Error converting certificate",
                                                 e);
        }


        try {
            certType = CertificateUtil.getCertificateType(tbsCert);
        } catch (CertificateException e) {
            throw new CertPathValidatorException(
                "Error obtaining certificate type", e);
        } catch (IOException e) {
            throw new CertPathValidatorException(
                "Error obtaining certificate type", e);
        }
        // validate the first certificate in chain
        checkCertificate(cert, certType);

        boolean isProxy = ProxyCertificateUtil.isProxy(certType);
        if (isProxy) {
            proxyDepth++;
        }

        for (int i = 1; i < certificates.size(); i++) {

            boolean certIsProxy = ProxyCertificateUtil.isProxy(certType);
            issuerCert = (X509Certificate)certificates.get(i);
            try {
                issuerTbsCert =
                    CertificateUtil.getTBSCertificateStructure(issuerCert);
            } catch (CertificateException e) {
                throw new CertPathValidatorException(
                    "Error converting certificate", e);
            } catch (IOException e) {
                throw new CertPathValidatorException(
                    "Error converting certificate", e);
            }

            try {

                issuerCertType =
                    CertificateUtil.getCertificateType(issuerTbsCert);
            } catch (CertificateException e) {
                throw new CertPathValidatorException(
                    "Error obtaining certificate type", e);
            } catch (IOException e) {
                throw new CertPathValidatorException(
                    "Error obtaining certificate type", e);
            }

            if (issuerCertType == Constants.CertificateType.CA) {
                // PC can only be signed by EEC or PC
                if (certIsProxy) {
                    throw new CertPathValidatorException(
                        "Proxy certificate can be signed only by EEC or Proxy " +
                        "Certificate. Certificate "
                        + cert.getSubjectDN() + " violates this.");
                }

                try {
                    int pathLen =
                        CertificateUtil.getCAPathConstraint(issuerTbsCert);
                    if (pathLen < Integer.MAX_VALUE &&
                        (i - proxyDepth - 1) > pathLen) {
                        throw new CertPathValidatorException(
                            "Path length constaint of certificate " +
                            issuerCert.getSubjectDN() + " voilated");
                    }
                } catch (IOException e) {
                    throw new CertPathValidatorException(
                        "Error obtaining CA Path constraint", e);
                }
            } else if (ProxyCertificateUtil.isGsi3Proxy(issuerCertType) ||
                       ProxyCertificateUtil.isGsi4Proxy(issuerCertType)) {
                if (ProxyCertificateUtil.isGsi3Proxy(issuerCertType)) {
                    if (!ProxyCertificateUtil.isGsi3Proxy(certType)) {
                        throw new CertPathValidatorException(
                            "Proxy certificate can only sign another proxy certificate of same type. Voilated by " +
                            issuerCert.getSubjectDN() + " issuing "
                            + cert.getSubjectDN());
                    }
                } else if (ProxyCertificateUtil.isGsi4Proxy(issuerCertType)) {
                    if (!ProxyCertificateUtil.isGsi4Proxy(certType)) {
                        throw new CertPathValidatorException(
                            "Proxy certificate can only sign another proxy certificate of same type. Voilated by " +
                            issuerCert.getSubjectDN() + " issuing "
                            + cert.getSubjectDN());
                    }
                }
                int pathLen;
                try {
                    pathLen = ProxyCertificateUtil
                        .getProxyPathConstraint(issuerTbsCert);
                } catch (IOException e) {
                    throw new CertPathValidatorException(
                        "Error obtaining proxy path constraint", e);
                }
                if (pathLen == 0) {
                    throw new CertPathValidatorException(
                        "Proxy path length constraint violated of certificate " +
                        issuerCert.getSubjectDN());
                }
                if (pathLen < Integer.MAX_VALUE &&
                    proxyDepth > pathLen) {
                    throw new CertPathValidatorException(
                        "Proxy path length constraint violated of certificate " +
                        issuerCert.getSubjectDN());
                }
                proxyDepth++;
            } else if (ProxyCertificateUtil.isGsi2Proxy(issuerCertType)) {
                // PC can sign EEC or another PC only
                if (!ProxyCertificateUtil.isGsi2Proxy(certType)) {
                    throw new CertPathValidatorException(
                        "Proxy certificate can only sign another proxy certificate of same type. Voilated by " +
                        issuerCert.getSubjectDN() + " issuing "
                        + cert.getSubjectDN());
                }
                proxyDepth++;
            } else if (issuerCertType == Constants.CertificateType.EEC) {
                if (!ProxyCertificateUtil.isProxy(certType)) {
                    throw new CertPathValidatorException(
                        "EEC can only sign another proxy certificate. Voilated by " +
                        issuerCert.getSubjectDN() + " issuing "
                        + cert.getSubjectDN());

                }
            } else {
                // this should never happen?
                throw new CertPathValidatorException(
                    "UNknown issuer type " + issuerCertType +
                    " for certificate " + issuerCert.getSubjectDN());
            }
            if (certIsProxy) {
                // check all the proxy & issuer constraints
                if (ProxyCertificateUtil.isGsi3Proxy(certType) ||
                    ProxyCertificateUtil.isGsi4Proxy(certType)) {
                    try {
                        checkProxyConstraints(tbsCert, issuerTbsCert, cert);
                    } catch (IOException e) {
                        throw new CertPathValidatorException(
                            "Proxy constraint check failed on " +
                            cert.getSubjectDN(), e);
                    }
                    if ((certType ==
                         Constants.CertificateType.GSI_3_RESTRICTED_PROXY)
                        || (certType ==
                            Constants.CertificateType.GSI_4_RESTRICTED_PROXY)) {
                        try {
                            checkRestrictedProxy(tbsCert, certPath, i);
                        } catch (IOException e) {
                            throw new CertPathValidatorException(
                                "Restricted proxy check failed on " +
                                cert.getSubjectDN(), e);
                        }
                    }
                }
            } else {

                try {
                    checkKeyUsage(issuerTbsCert);
                } catch (IOException e) {
                    throw new CertPathValidatorException(
                        "Key usage check failed on " +
                        issuerCert.getSubjectDN(), e);
                }
            }

            checkCertificate(issuerCert, issuerCertType);

            cert = issuerCert;
            certType = issuerCertType;
            tbsCert = issuerTbsCert;

        }

        return new X509ProxyCertPathValidatorResult(this.identityCert,
                                                    this.limited);

    }

    /**
     * Method that validates the provided cert path to find a trusted
     * certificate in the certificate store.
     * <p/>
     * For each certificate i in certPath, it is expected that the i+1
     * certificate is the issuer of the certificate path. See CertPath.
     * <p/>
     * For each certificate i in certpath, validate signature of certificate i
     * get issuer of certificate i get certificate i+i ensure that the
     * certificate i+1 is issuer of certificate i If not, throw an exception for
     * illegal argument validate signature of i+1 Throw exception if it does not
     * validate check if i+1 is a trusted certificate in the trust store. If so
     * return certpath until i+1 If not, continue; If all certificates in the
     * certpath have been checked and none exisits in trust store, check if
     * trust store has certificate of issuer of last certificate in CertPath. If
     * so, return certPath + trusted certificate from trust store If not, throw
     * an exception for lack of valid trust root.
     *
     * @param certPath
     * @return
     * @throws CertPathValidatorException
     */
    protected CertPath findTrustedCertPath(CertPath certPath)
        throws CertPathValidatorException {

        // This will be the cert path to return
        List<X509Certificate> trustedCertPath =
            new ArrayList<X509Certificate>();
        // This is the certs to validate
        List<? extends Certificate> certs = certPath.getCertificates();

        X509Certificate x509Certificate = null;
        int index = 0;
        int certsSize = certs.size();

        Certificate certificate = certs.get(index);
        if (!(certificate instanceof X509Certificate)) {
            throw new CertPathValidatorException(
                "Certificate of type " + X509Certificate.class.getName() +
                " required");
        }
        x509Certificate = (X509Certificate)certificate;

        while (index < certsSize) {

            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setCertificate(x509Certificate);
            Collection<? extends Certificate> caCerts;
            try {
                caCerts = KeyStoreUtil
                    .getTrustedCertificates(this.keyStore, certSelector);
            } catch (KeyStoreException e) {
                throw new CertPathValidatorException(
                    "Error accessing trusted certificate store", e);
            }
            if (caCerts.size() > 0) {

                trustedCertPath.add(x509Certificate);
                // FIXME: does this have to be a CA certificate and/or self signed
                // such that signature is validated.
                // trusted certificate found. return.
                try {
                    CertificateFactory certFac =
                        CertificateFactory.getInstance("X.509");
                    return certFac.generateCertPath(trustedCertPath);
                } catch (CertificateException e) {
                    throw new CertPathValidatorException(
                        "Error generating trusted certificate path", e);
                }
            }

            if (index + 1 >= certsSize) {
                break;
            }

            index++;
            Certificate issuerCertificate = certs.get(index);
            if (!(certificate instanceof X509Certificate)) {
                throw new CertPathValidatorException(
                    "Certificate of type " + X509Certificate.class.getName() +
                    " required");
            }
            X509Certificate x509IssuerCertificate =
                (X509Certificate)issuerCertificate;

            // check that the next one is indeed issuer
            Principal issuerDN = x509Certificate.getIssuerDN();
            Principal issuerCertDN = x509IssuerCertificate.getSubjectDN();
            if (!(issuerDN.equals(issuerCertDN))) {
                throw new IllegalArgumentException(
                    "Incorrect certificate path, certificate in chain can only " +
                    "be issuer of previous certificate");
            }

            // validate integrity of signature                                                                          
            PublicKey publicKey = x509IssuerCertificate.getPublicKey();
            try {
                x509Certificate.verify(publicKey);
            } catch (CertificateException e) {
                throw new CertPathValidatorException(
                    "Signature validation on the certificate " +
                    x509Certificate.getSubjectDN(), e);
            } catch (NoSuchAlgorithmException e) {
                throw new CertPathValidatorException(
                    "Signature validation on the certificate " +
                    x509Certificate.getSubjectDN(), e);
            } catch (InvalidKeyException e) {
                throw new CertPathValidatorException(
                    "Signature validation on the certificate " +
                    x509Certificate.getSubjectDN(), e);
            } catch (NoSuchProviderException e) {
                throw new CertPathValidatorException(
                    "Signature validation on the certificate " +
                    x509Certificate.getSubjectDN(), e);
            } catch (SignatureException e) {
                throw new CertPathValidatorException(
                    "Signature validation on the certificate " +
                    x509Certificate.getSubjectDN(), e);
            }

            trustedCertPath.add(x509Certificate);
            x509Certificate = x509IssuerCertificate;

        }

        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(x509Certificate.getIssuerX500Principal());
        Collection<? extends Certificate> caCerts;
        try {
            caCerts =
                KeyStoreUtil.getTrustedCertificates(this.keyStore, selector);
        } catch (KeyStoreException e) {
            throw new CertPathValidatorException(e);
        }
        if (caCerts.size() < 1) {
            throw new CertPathValidatorException(
                "No trusted path can be constructed");
        }

        trustedCertPath.add(x509Certificate);
        // FIXME: unchecked cast here. does the last certificate need to be validated?
        trustedCertPath.add((X509Certificate)caCerts.iterator().next());

        try {
            CertificateFactory certFac =
                CertificateFactory.getInstance("X.509");
            return certFac.generateCertPath(trustedCertPath);
        } catch (CertificateException e) {
            throw new CertPathValidatorException(
                "Error generating trusted certificate path", e);
        }

    }

    /**
     * Method that checks the time validity. Uses the standard
     * Certificate.checkValidity method.
     *
     * @throws CertPathValidatorException If certificate has expired or is not
     *                                    yet valid.
     */
    protected void checkCertificateDateValidity(X509Certificate cert)
        throws CertPathValidatorException {

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

    /**
     * Method that checks if there are unsupported critical extension. Supported
     * ones are only BasicConstrains, KeyUsage, Proxy Certificate (old and new)
     *
     * @throws CertPathValidatorException If any critical extension that is not
     *                                    supported is in the certificate.
     *                                    Anything other than those listed above
     *                                    will trigger the exception.
     */
    protected void
    checkUnsupportedCriticalExtensions(X509Certificate certificate,
                                       Constants.CertificateType certType)
        throws CertPathValidatorException {


        Set<String> criticalExtensionOids =
            certificate.getCriticalExtensionOIDs();
        if (criticalExtensionOids == null) {
            return;
        }
        Iterator<String> iterator = criticalExtensionOids.iterator();
        while (iterator.hasNext()) {
            String oid = iterator.next();
            if (oid.equals(BASIC_CONSTRAINT_OID) ||
                oid.equals(KEY_USAGE_OID) ||
                (oid.equals(ProxyCertInfo.OID.toString()) &&
                 ProxyCertificateUtil.isGsi4Proxy(certType)) ||
                (oid.equals(ProxyCertInfo.OLD_OID.toString()) &&
                 ProxyCertificateUtil.isGsi3Proxy(certType))) {
            } else {
                throw new CertPathValidatorException(
                    "Critical extension with unsupported OID " + oid);
            }

        }
    }


    /**
     * Method that sets the identity of the certificate path. Also checks if
     * limited proxy is acceptable.
     *
     * @throws CertPathValidatorException If limited proxies are not accepted
     *                                    and the chain has a limited proxy.
     */
    protected void checkIdentity(X509Certificate cert,
                                 Constants.CertificateType certType)
        throws CertPathValidatorException {

        if (this.identityCert == null) {
            // check if limited
            if (ProxyCertificateUtil.isLimitedProxy(certType)) {
                this.limited = true;

                if (this.rejectLimitedProxy) {
                    throw new CertPathValidatorException(
                        "Limited proxy not accepted");
                }
            }

            // set the identity cert
            if (!ProxyCertificateUtil.isImpersonationProxy(certType)) {
                this.identityCert = cert;
            }
        }
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
    protected void checkCRL(X509Certificate cert)
        throws CertPathValidatorException {

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

        Iterator crlsIterator = crls.iterator();
        while (crlsIterator.hasNext()) {

            X509CRL crl = (X509CRL)crlsIterator.next();

            // if expired, will throw error.
            checkCRLDateValidity(crl);

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


    /**
     * Validate DN against the signing policy
     *
     * @param certificate
     * @throws CertPathValidatorException
     */
    protected void checkSigningPolicy(X509Certificate certificate)
        throws CertPathValidatorException {

        X500Principal caPrincipal = certificate.getIssuerX500Principal();
        SigningPolicy policy;
        try {
            policy = this.policyStore.getSigningPolicy(caPrincipal);
        } catch (CertStoreException e) {
            throw new CertPathValidatorException(e);
        }

        if (policy == null) {
            throw new CertPathValidatorException(
                "No signing policy for " + certificate.getIssuerDN());
        }

        boolean valid =
            policy.isValidSubject(certificate.getSubjectX500Principal());

        if (!valid) {
            throw new CertPathValidatorException(
                "Certificate " + certificate.getSubjectDN() +
                " voilates signing policy for CA " + caPrincipal.getName());
        }

    }

    protected void checkRestrictedProxy(TBSCertificateStructure proxy,
                                        CertPath certPath,
                                        int index)
        throws CertPathValidatorException, IOException {


        ProxyCertInfo info = ProxyCertificateUtil.getProxyCertInfo(proxy);
        ProxyPolicy policy = info.getProxyPolicy();

        String pl = policy.getPolicyLanguage().getId();

        ProxyPolicyHandler handler = null;
        if (this.policyHandlers != null) {
            handler = this.policyHandlers.get(pl);
        }

        if (handler == null) {
            throw new CertPathValidatorException(
                "Unknown policy, no handler registered to validate policy " +
                pl);

        }

        handler.validate(info, certPath, index);

    }

    protected void checkKeyUsage(TBSCertificateStructure issuer)
        throws CertPathValidatorException, IOException {

        boolean[] issuerKeyUsage = CertificateUtil.getKeyUsage(issuer);
        if (issuerKeyUsage != null) {
            if (!issuerKeyUsage[5]) {
                throw new CertPathValidatorException(
                    "Certificate " + issuer.getSubject() +
                    " violated key usage policy.");
            }
        }
    }

    /**
     * Method to check following for any given certificate
     * <p/>
     * a) Date validity, is it valid for the curent time (see
     * checkCertificateDateValidity()) b) Any unsupported critical extensions
     * (see checkUnsupportedCriticalExtensions()) c) Identity of certificate
     * (see checkIdentity()) d) Revocation (see checkCRL()) s) Signing policy
     * (see chechSigningPolicy())
     *
     * @param cert
     * @param certType
     * @throws CertPathValidatorException
     * @
     */
    private void checkCertificate(X509Certificate cert,
                                  Constants.CertificateType certType)
        throws CertPathValidatorException {

        checkCertificateDateValidity(cert);

        checkUnsupportedCriticalExtensions(cert, certType);

        checkIdentity(cert, certType);

        checkCRL(cert);

        // signing policy check
        if (requireSigningPolicyCheck(certType)) {
            checkSigningPolicy(cert);
        }

    }

    /**
     * if a certificate is not a CA or if it is not a proxy, return true.
     */
    private boolean requireSigningPolicyCheck(
        Constants.CertificateType certType) {

        if (ProxyCertificateUtil.isProxy(certType) ||
            (certType == Constants.CertificateType.CA)) {
            return false;
        }
        return true;
    }

    protected void checkProxyConstraints(TBSCertificateStructure proxy,
                                         TBSCertificateStructure issuer,
                                         X509Certificate checkedProxy)
        throws CertPathValidatorException, IOException {

        X509Extensions extensions;
        DERObjectIdentifier oid;
        X509Extension proxyExtension;

        X509Extension proxyKeyUsage = null;

        extensions = proxy.getExtensions();
        if (extensions != null) {
            Enumeration e = extensions.oids();
            while (e.hasMoreElements()) {
                oid = (DERObjectIdentifier)e.nextElement();
                proxyExtension = extensions.getExtension(oid);
                if (oid.equals(X509Extensions.SubjectAlternativeName) ||
                    oid.equals(X509Extensions.IssuerAlternativeName)) {
                    // No Alt name extensions - 3.2 & 3.5
                    throw new CertPathValidatorException(
                        "Proxy violation: no Subject or Issuer Alternative Name");
                } else if (oid.equals(X509Extensions.BasicConstraints)) {
                    // Basic Constraint must not be true - 3.8
                    BasicConstraints basicExt =
                        CertificateUtil.getBasicConstraints(proxyExtension);
                    if (basicExt.isCA()) {
                        throw new CertPathValidatorException(
                            "Proxy violation: Basic Constraint CA is set to true");
                    }
                } else if (oid.equals(X509Extensions.KeyUsage)) {
                    proxyKeyUsage = proxyExtension;

                    boolean[] keyUsage =
                        CertificateUtil.getKeyUsage(proxyExtension);
                    // these must not be asserted
                    if (keyUsage[1] ||
                        keyUsage[5]) {
                        throw new CertPathValidatorException(
                            "Proxy violation: Key usage is asserted.");
                    }
                    boolean[] issuerKeyUsage =
                        CertificateUtil.getKeyUsage(issuer);
                    if (issuerKeyUsage != null) {
                        for (int i = 0; i < 9; i++) {
                            if (i == 1 || i == 5) {
                                continue;
                            }
                            if (!issuerKeyUsage[i] && keyUsage[i]) {
                                throw new CertPathValidatorException(
                                    "Proxy violation: Issuer key usage is incorrect");
                            }
                        }
                    }
                }
            }
        }

        extensions = issuer.getExtensions();

        if (extensions != null) {
            Enumeration e = extensions.oids();
            while (e.hasMoreElements()) {
                oid = (DERObjectIdentifier)e.nextElement();
                proxyExtension = extensions.getExtension(oid);
                if (oid.equals(X509Extensions.KeyUsage)) {
                    // If issuer has it then proxy must have it also
                    if (proxyKeyUsage == null) {
                        throw new CertPathValidatorException(
                            "Proxy violation: Issuer has key usage, but proxy does not");
                    }
                    // If issuer has it as critical so does the proxy
                    if (proxyExtension.isCritical() &&
                        !proxyKeyUsage.isCritical()) {
                        throw new CertPathValidatorException(
                            "Proxy voilation: issuer key usage is critical, but proxy certificate's is not");
                    }
                }
            }
        }

    }

}

