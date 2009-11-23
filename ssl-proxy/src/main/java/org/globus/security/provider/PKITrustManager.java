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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Vector;

import javax.net.ssl.X509TrustManager;

import org.globus.security.X509ProxyCertPathParameters;
import org.globus.security.util.CertificateLoadUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 *         <p/>
 *         FIXME: ability to accept anonymous connections?
 */
public class PKITrustManager implements X509TrustManager {

    private Logger logger = LoggerFactory.getLogger(getClass());

    CertPathValidatorSpi validator;
    X509ProxyCertPathParameters parameters;
    CertPathValidatorResult result;

    public PKITrustManager(CertPathValidatorSpi validator_,
                           X509ProxyCertPathParameters parameters_) {

        if (validator_ == null) {
            throw new IllegalArgumentException("Validator cannot be null");
        }

        if (parameters_ == null) {
            throw new IllegalArgumentException("Parameter cannot be null");
        }


        if (!(parameters_ instanceof X509ProxyCertPathParameters)) {
            throw new IllegalArgumentException(
                    "Parameter has to be an instance of "
                            + X509ProxyCertPathParameters.class.getName());
        }

        this.validator = validator_;
        this.parameters = parameters_;
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
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

    public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
            throws CertificateException {

        CertPath certPath = getCertPath(x509Certificates);
        try {
            this.result = this.validator
                    .engineValidate(certPath, parameters);
        } catch (CertPathValidatorException exception) {
            throw new CertificateException("Path validation failed. " + exception.getMessage(), exception);
        } catch (InvalidAlgorithmParameterException exception) {
            throw new CertificateException("Path validation failed. " + exception.getMessage(), exception);
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        try {
            Collection<X509Certificate> trusted =
                    CertificateLoadUtil.getTrustedCertificates(
                            this.parameters.getKeyStore(), null);
            X509Certificate[] trustedCerts =
                    trusted.toArray(new X509Certificate[trusted.size()]);
            return trustedCerts;
        } catch (KeyStoreException e) {
            logger.warn(
                    "Unable to load trusted Certificates.  Authentication will fail.");
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
        List<X509Certificate> certList =
                new Vector<X509Certificate>(certs.length);
        certList.addAll(Arrays.asList(certs));
        CertPath certPath = factory.generateCertPath(certList);
        logger.debug("CertPath: {}", certPath.toString());
        return certPath;
    }
}
