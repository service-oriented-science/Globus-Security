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

import org.globus.security.SigningPolicyStore;
import org.globus.security.X509ProxyCertPathParameters;
import org.globus.security.X509ProxyCertPathValidatorResult;
import org.globus.security.provider.X509ProxyCertPathValidator;
import org.globus.security.proxyExtension.ProxyPolicyHandler;
import org.globus.security.util.CertificateLoadUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509TrustManager;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Vector;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 *         <p/>
 *         FIXME: ability to accept anonymous connections?
 */
public class PKITrustManager implements X509TrustManager {
    private Logger logger = LoggerFactory.getLogger(getClass());
    X509ProxyCertPathValidator validator;
    X509ProxyCertPathParameters parameters;
    X509ProxyCertPathValidatorResult result;

    public PKITrustManager(KeyStore keyStore, CertStore certStore,
                           SigningPolicyStore policyStore) {

        this(keyStore, certStore, policyStore, false, null);
    }

    public PKITrustManager(KeyStore keyStore, CertStore certStore,
                           SigningPolicyStore policyStore,
                           boolean rejectLimitedProxy) {
        this(keyStore, certStore, policyStore, rejectLimitedProxy, null);
    }

    public PKITrustManager(KeyStore keyStore, CertStore certStore,
                           SigningPolicyStore policyStore,
                           boolean rejectLimitedProxy,
                           Map<String, ProxyPolicyHandler> policyHandlers) {

        parameters =
                new X509ProxyCertPathParameters(keyStore, certStore, policyStore,
                        rejectLimitedProxy,
                        policyHandlers);
        
        validator = new X509ProxyCertPathValidator();

    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
            throws CertificateException {


        logger.info("In Globus Provider");


        // FIXME: anonymous clients?
        CertPath certPath = getCertPath(x509Certificates);
        try {
            this.result = (X509ProxyCertPathValidatorResult) this.validator
                    .engineValidate(certPath, parameters);
        } catch (CertPathValidatorException exception) {
            throw new CertificateException("Pathvalidation failed", exception);
        } catch (InvalidAlgorithmParameterException exception) {
            throw new CertificateException("Pathvalidation failed", exception);
        }
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
            throws CertificateException {

        CertPath certPath = getCertPath(x509Certificates);
        try {
            this.result = (X509ProxyCertPathValidatorResult) this.validator
                    .engineValidate(certPath, parameters);
        } catch (CertPathValidatorException exception) {
            throw new CertificateException("Pathvalidation failed", exception);
        } catch (InvalidAlgorithmParameterException exception) {
            throw new CertificateException("Pathvalidation failed", exception);
        }
    }

    // FIXME:
    public X509Certificate[] getAcceptedIssuers() {
        try {
            Collection<X509Certificate> trusted = 
                    CertificateLoadUtil.getTrustedCertificates(
                            this.parameters.getKeyStore(), null);
            X509Certificate[] trustedCerts = trusted.toArray(new X509Certificate[trusted.size()]);
            return trustedCerts;
        } catch (KeyStoreException e) {
            logger.warn("Unable to load trusted Certificates.  No authentication will occur.");
            return new X509Certificate[]{};
        }
    }

    public CertPathValidatorResult getValidationResult() {
        return this.result;
    }

    // FIXME: THis is super naive, fix it.
    private CertPath getCertPath(X509Certificate[] certs)
            throws CertificateException {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certList = new Vector<X509Certificate>(certs.length);
        certList.addAll(Arrays.asList(certs));
        CertPath certPath = factory.generateCertPath(certList);
        logger.debug("CertPath: {}", certPath.toString());
        return certPath;
    }
}
