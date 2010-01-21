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

package org.globus.security.util;

import org.globus.security.SigningPolicyStoreParameters;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Oct 15, 2009
 * Time: 7:34:57 PM
 * To change this template use File | Settings | File Templates.
 * FIXME: does this take null passwords for keystore and certstore?
 */
public class SSLConfigurator {

    public static final String DEFAULT_KEYSTORE = System.getProperty("user.home") + File.separator
            + ".keystore";
    private CertStoreParameters certStoreParameters;
    private String provider;
    private String protocol = "TLS";
    private String secureRandomAlgorithm;
    private SigningPolicyStoreParameters signingPolicyStoreParameters;
    private String keyStore = DEFAULT_KEYSTORE;
    private String keyStoreType = "JKS";
    private String keyPassword;
    private String keyStorePassword;
    private String sslKeyManagerFactoryAlgorithm =
            Security.getProperty("ssl.KeyManagerFactory.algorithm") == null ? "SunX509" : Security.getProperty(
                    "ssl.KeyManagerFactory.algorithm"); // cert algorithm;
//    private String sslTrustManagerFactoryAlgorithm =
//            Security.getProperty("ssl.TrustManagerFactory.algorithm") == null
//                    ? "PKITrustManager"
//                    : Security.getProperty("ssl.TrustManagerFactory.algorithm");
    private String trustStoreType = "PEMFilebasedKeyStore";
    private KeyStore.LoadStoreParameter trustStoreParameters;
    private String trustStorePath;
    private String trustStorePassword;
    private String certStoreType = "PEMFilebasedCertStore";

    public SSLSocketFactory createFactory() throws Exception {
        KeyManager[] keyManagers = loadKeyManagers();

        KeyStore trustStore = loadTrustStore();

        CertStore certStore = CertStore.getInstance(certStoreType, certStoreParameters);
        TrustManager[] trustManagers = loadTrustManagers(trustStore, certStore);

        SecureRandom secureRandom = loadSecureRandom();

        SSLContext context = loadSSLContext();

        context.init(keyManagers, trustManagers, secureRandom);
        return context.getSocketFactory();
    }

    public SSLServerSocketFactory createServerFactory() throws Exception {
        KeyManager[] keyManagers = loadKeyManagers();

        KeyStore trustStore = loadTrustStore();

        CertStore certStore = CertStore.getInstance("PEMFilebasedCertStore", certStoreParameters);

        TrustManager[] trustManagers = loadTrustManagers(trustStore, certStore);

        SecureRandom secureRandom = loadSecureRandom();

        SSLContext context = loadSSLContext();

        context.init(keyManagers, trustManagers, secureRandom);
        return context.getServerSocketFactory();
    }

    private SSLContext loadSSLContext() throws NoSuchAlgorithmException, NoSuchProviderException {
        return provider == null
                ? SSLContext.getInstance(protocol)
                : SSLContext.getInstance(protocol, provider);
    }

    private SecureRandom loadSecureRandom() throws NoSuchAlgorithmException {
        return secureRandomAlgorithm == null
                ? null
                : SecureRandom.getInstance(secureRandomAlgorithm);
    }

    // FIXME: limited proxy policy and configurable policy handlers...

    private TrustManager[] loadTrustManagers(KeyStore trustStore, CertStore certStore)
            throws InvalidAlgorithmParameterException {
//        FileBasedSigningPolicyStore spStore = new FileBasedSigningPolicyStore(signingPolicyStoreParameters);
//        X509ProxyCertPathValidator validator = new X509ProxyCertPathValidator();
//        X509ProxyCertPathParameters parameters =
// new X509ProxyCertPathParameters(trustStore, certStore, spStore, false);
//        TrustManager tm = new PKITrustManager(validator, parameters);
//        return new TrustManager[]{tm};
        return new TrustManager[0];
    }

    private KeyManager[] loadKeyManagers()
            throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
            UnrecoverableKeyException {
        InputStream keystoreInputStream = null;

        if (keyStore != null) {
            keystoreInputStream = getResource(keyStore);
        }

        KeyStore keyStoreToLoad = KeyStore.getInstance(keyStoreType);
        keyStoreToLoad.load(keystoreInputStream, keyPassword == null ? null : keyPassword.toCharArray());


        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(sslKeyManagerFactoryAlgorithm);
        keyManagerFactory.init(keyStoreToLoad,
                keyStorePassword == null
                        ? null
                        : keyStorePassword.toCharArray());
        return keyManagerFactory.getKeyManagers();
    }

    private KeyStore loadTrustStore()
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore trustStore = KeyStore.getInstance(trustStoreType);
        if (trustStoreParameters == null) {
            if (this.trustStorePath == null || this.trustStorePassword == null) {
                this.trustStorePath = this.keyStore;
                this.trustStorePassword = this.keyStorePassword;
            }
            InputStream trustStoreInputStream =
                    getResource(trustStorePath);
            char[] pw = trustStorePassword == null
                    ? null
                    : trustStorePassword.toCharArray();
            trustStore.load(trustStoreInputStream, pw);
            return trustStore;
        }
        trustStore.load(this.trustStoreParameters);
        return trustStore;
    }

    private InputStream getResource(String source) throws IOException {
        InputStream is;
        try {
            URL url = new URL(source);
            is = url.openStream();
        } catch (MalformedURLException e) {
            File file = new File(source);
            if (file.exists()) {
                is = new FileInputStream(file);
            } else {
                is = getClass().getClassLoader().getResource(source).openStream();
            }
        }
        return is;
    }

    public CertStoreParameters getCertStoreParameters() {
        return certStoreParameters;
    }

    public void setCertStoreParameters(CertStoreParameters certStoreParameters) {
        this.certStoreParameters = certStoreParameters;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getSecureRandomAlgorithm() {
        return secureRandomAlgorithm;
    }

    public void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
        this.secureRandomAlgorithm = secureRandomAlgorithm;
    }

    public SigningPolicyStoreParameters getSigningPolicyStoreParameters() {
        return signingPolicyStoreParameters;
    }

    public void setSigningPolicyStoreParameters(SigningPolicyStoreParameters signingPolicyStoreParameters) {
        this.signingPolicyStoreParameters = signingPolicyStoreParameters;
    }

    public String getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(String keyStore) {
        this.keyStore = keyStore;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getKeyPassword() {
        return this.keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public String getSslKeyManagerFactoryAlgorithm() {
        return sslKeyManagerFactoryAlgorithm;
    }

    public void setSslKeyManagerFactoryAlgorithm(String sslKeyManagerFactoryAlgorithm) {
        this.sslKeyManagerFactoryAlgorithm = sslKeyManagerFactoryAlgorithm;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getTrustStoreType() {
        return trustStoreType;
    }

    public void setTrustStoreType(String trustStoreType) {
        this.trustStoreType = trustStoreType;
    }

    public KeyStore.LoadStoreParameter getTrustStoreParameters() {
        return trustStoreParameters;
    }

    public void setTrustStoreParameters(KeyStore.LoadStoreParameter trustStoreParameters) {
        this.trustStoreParameters = trustStoreParameters;
    }

    public String getTrustStorePath() {
        return trustStorePath;
    }

    public void setTrustStorePath(String trustStorePath) {
        this.trustStorePath = trustStorePath;
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }

//    public void setSslTrustManagerFactoryAlgorithm(String sslTrustManagerFactoryAlgorithm) {
//        this.sslTrustManagerFactoryAlgorithm = sslTrustManagerFactoryAlgorithm;
//    }
}
