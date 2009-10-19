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
package org.globus.security;

import org.globus.security.provider.X509ProxyCertPathValidator;
import org.globus.security.proxyExtension.ProxyPolicyHandler;

import javax.net.ssl.X509TrustManager;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Vector;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 *         <p/>
 *         FIXME: ability to accept anonymous connections? // Rework this, so
 *         validator creation is not hardcoded.
 */
public class PKITrustManager implements X509TrustManager {

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

    /**
     * @param keyStore           Contains all trusted CA certificates for use in
     *                           validation
     * @param certStore          Contains CRLs for use in validation. Any
     *                           certificates stored here is not used.
     * @param policyStore        Contains signing policy for use in validation
     * @param rejectLimitedProxy Parameter determines if validator should reject
     *                           limited proxy certificates presented by remote
     *                           entity.
     * @param policyHandlers     Map of policy OID to handlers for processing
     *                           custom extensions in certificates.
     */
    public PKITrustManager(KeyStore keyStore, CertStore certStore,
                           SigningPolicyStore policyStore,
                           boolean rejectLimitedProxy,
                           Map<String, ProxyPolicyHandler> policyHandlers) {


        initializeValidator(keyStore, certStore, policyStore,
                            rejectLimitedProxy,
                            policyHandlers);
    }

    protected void initializeValidator(KeyStore keyStore, CertStore certStore,
                                       SigningPolicyStore policyStore,
                                       boolean rejectLimitedProxy,
                                       Map<String, ProxyPolicyHandler> policyHandlers) {

        this.parameters =
            new X509ProxyCertPathParameters(keyStore, certStore, policyStore,
                                            rejectLimitedProxy,
                                            policyHandlers);

        this.validator = new X509ProxyCertPathValidator();
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates,
                                   String authType)
        throws CertificateException {

        // FIXME: authType checking?
        // FIXME: anonymous clients?
        CertPath certPath = getCertPath(x509Certificates);
        try {
            this.result = (X509ProxyCertPathValidatorResult)this.validator
                .engineValidate(certPath, parameters);
        } catch (CertPathValidatorException exception) {
            throw new CertificateException("Pathvalidation failed", exception);
        } catch (InvalidAlgorithmParameterException exception) {
            throw new CertificateException("Pathvalidation failed", exception);
        }
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates,
                                   String authType)
        throws CertificateException {

        // FIXME: authType checking?

        CertPath certPath = getCertPath(x509Certificates);
        try {
            this.result = (X509ProxyCertPathValidatorResult)this.validator
                .engineValidate(certPath, parameters);
        } catch (CertPathValidatorException exception) {
            throw new CertificateException("Pathvalidation failed", exception);
        } catch (InvalidAlgorithmParameterException exception) {
            throw new CertificateException("Pathvalidation failed", exception);
        }
    }

    // FIXME:
    public X509Certificate[] getAcceptedIssuers() {
        KeyStore trustedStore = this.parameters.getKeyStore();
        return new X509Certificate[0];  //To change body of implemented methods use File | Settings | File Templates.
    }

    public CertPathValidatorResult getValidationResult() {
        return this.result;
    }

    // FIXME: THis is super naive, fix it.
    private CertPath getCertPath(X509Certificate[] certs)
        throws CertificateException {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List certList = new Vector(certs.length);
        for (int i = 0; i < certs.length; i++) {
            certList.add(certs[i]);
        }
        CertPath certPath = factory.generateCertPath(certList);
        return certPath;
    }
}
