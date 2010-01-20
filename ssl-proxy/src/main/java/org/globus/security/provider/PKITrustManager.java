/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
package org.globus.security.provider;

import org.globus.security.X509ProxyCertPathParameters;
import org.globus.security.util.CertificateLoadUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509TrustManager;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Vector;

/**
 * This is an implementation of an X509TrustManager which supports the validation of proxy certificates.
 * It uses the Globus CertPathValidator.
 * <p/>
 * FIXME: ability to accept anonymous connections?
 *
 * @version ${version}
 * @since 1.0
 */
public class PKITrustManager implements X509TrustManager {

    private CertPathValidatorSpi validator;
    private X509ProxyCertPathParameters parameters;
    private CertPathValidatorResult result;
    private Logger logger = LoggerFactory.getLogger(getClass());


    /**
     * Create a trust manager with the pre-configured cert path validator and proxy parameters.
     *
     * @param initValidator  A cert path validator to be used by this trust manager.
     * @param initParameters The proxy cert parameters, populated with trust store, cert store, etc.
     */
    public PKITrustManager(CertPathValidatorSpi initValidator, X509ProxyCertPathParameters initParameters) {

        if (initValidator == null) {
            throw new IllegalArgumentException("Validator cannot be null");
        }

        if (initParameters == null) {
            throw new IllegalArgumentException("Parameter cannot be null");
        }

        this.validator = initValidator;
        this.parameters = initParameters;
    }

    /**
     * Test if the client is trusted based on the certificate chain. Does not currently support anonymous clients.
     *
     * @param x509Certificates The certificate chain to test for validity.
     * @param authType         The authentication type based on the client certificate.
     * @throws CertificateException If the path validation fails.
     */
    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType)
            throws CertificateException {
        // FIXME: anonymous clients?
        CertPath certPath = getCertPath(x509Certificates);
        try {
            this.result = this.validator.engineValidate(certPath, parameters);
        } catch (CertPathValidatorException exception) {
            throw new CertificateException("Pathvalidation failed", exception);
        } catch (InvalidAlgorithmParameterException exception) {
            throw new CertificateException("Pathvalidation failed", exception);
        }
    }

    /**
     * Test if the server is trusted based on the certificate chain.
     *
     * @param x509Certificates The certificate chain to test for validity.
     * @param authType         The authentication type based on the server certificate.
     * @throws CertificateException If the path validation fails.
     */
    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType)
            throws CertificateException {
        CertPath certPath = getCertPath(x509Certificates);
        try {
            this.result = this.validator.engineValidate(certPath, parameters);
        } catch (CertPathValidatorException exception) {
            throw new CertificateException("Path validation failed. " + exception.getMessage(), exception);
        } catch (InvalidAlgorithmParameterException exception) {
            throw new CertificateException("Path validation failed. " + exception.getMessage(), exception);
        }
    }

    /**
     * Get the collection of trusted certificate issuers.
     *
     * @return The trusted certificate issuers.
     */
    public X509Certificate[] getAcceptedIssuers() {
        try {
            Collection<X509Certificate> trusted = CertificateLoadUtil.getTrustedCertificates(
                    this.parameters.getKeyStore(), null);
            return trusted.toArray(new X509Certificate[trusted.size()]);
        } catch (KeyStoreException e) {
            logger.warn(
                    "Unable to load trusted Certificates.  Authentication will fail.");
            return new X509Certificate[]{};
        }
    }

    /**
     * Return the result of the last certificate validation.
     *
     * @return The validation result.
     */
    public CertPathValidatorResult getValidationResult() {
        return this.result;
    }

    // FIXME: THis is super naive, fix it.

    private CertPath getCertPath(X509Certificate[] certs)
            throws CertificateException {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certList =
                new Vector<X509Certificate>(certs.length);
        certList.addAll(Arrays.asList(certs));
        CertPath certPath = factory.generateCertPath(certList);
        logger.debug("CertPath: {}", certPath.toString());
        return certPath;
    }
}
