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

import org.globus.security.SigningPolicyStore;
import org.globus.security.X509ProxyCertPathParameters;
import org.globus.security.provider.PKITrustManager;
import org.globus.security.provider.X509ProxyCertPathValidator;
import org.globus.security.proxyExtension.ProxyPolicyHandler;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.util.Map;

/**
 * This class is used to configure and create SSL socket factories.  The factories can either be built by setting
 * the keyStore, certStore, trustStore and policyStore directly, or it can use the java security SPI mechanism.
 * This is the simplest way to configure the globus ssl support.
 *
 * @version ${version}
 * @since 1.0
 */
public class SSLConfigurator {

    private String provider;
    private String protocol = "TLS";
    private String secureRandomAlgorithm;

    private KeyStore keyStore;
    private KeyStore trustStore;
    private CertStore certStore;
    private SigningPolicyStore policyStore;
    private boolean rejectLimitProxy;
    private Map<String, ProxyPolicyHandler> handlers;

    private String trustStoreType;
    private String trustStoreLocation;
    private String trustStorePassword;

    private String keyStoreType;
    private String keyStoreLocation;
    private String keyStorePassword;

    private String certStoreType;
    private CertStoreParameters certStoreParams;

    private String[] enabledCipherSuites;


    private String sslKeyManagerFactoryAlgorithm =
            Security.getProperty("ssl.KeyManagerFactory.algorithm") == null ? "SunX509" : Security.getProperty(
                    "ssl.KeyManagerFactory.algorithm");

    /**
     * Create an SSLSocketFactory based on the configured stores.
     *
     * @return A configured SSLSocketFactory
     * @throws GlobusSSLConfigurationException
     *          If we fail to create the socketFactory.
     */
    public SSLSocketFactory createFactory() throws GlobusSSLConfigurationException {
        SSLContext context = configureContext();
        return context.getSocketFactory();
    }


    /**
     * Create an SSLServerSocketFactory based on the configured stores.
     *
     * @return A configured SSLServerSocketFactory
     * @throws GlobusSSLConfigurationException
     *          If we fail to create the server socket factory.
     */
    public SSLServerSocketFactory createServerFactory() throws GlobusSSLConfigurationException {
        SSLContext context = configureContext();
        return context.getServerSocketFactory();
    }

    private SSLContext configureContext() throws GlobusSSLConfigurationException {

        X509ProxyCertPathParameters parameters = getCertPathParameters();

        TrustManager trustManager = new PKITrustManager(new X509ProxyCertPathValidator(), parameters);

        TrustManager[] trustManagers = new TrustManager[]{trustManager};

        KeyManager[] keyManagers = loadKeyManagers();

        SecureRandom secureRandom = loadSecureRandom();

        SSLContext context = loadSSLContext();

        try {
            context.init(keyManagers, trustManagers, secureRandom);
        } catch (KeyManagementException e) {
            throw new GlobusSSLConfigurationException(e);
        }

        return context;
    }

    private X509ProxyCertPathParameters getCertPathParameters() throws GlobusSSLConfigurationException {
        X509ProxyCertPathParameters parameters;
        KeyStore inputKeyStore = findTrustStore();
        CertStore inputCertStore = findCertStore();
        if (handlers == null) {
            parameters = new X509ProxyCertPathParameters(inputKeyStore, inputCertStore, this.policyStore,
                    this.rejectLimitProxy);
        } else {
            parameters = new X509ProxyCertPathParameters(inputKeyStore, inputCertStore, this.policyStore,
                    this.rejectLimitProxy, handlers);
        }
        return parameters;
    }


    private SSLContext loadSSLContext() throws GlobusSSLConfigurationException {
        try {
            return provider == null ? SSLContext.getInstance(protocol) : SSLContext.getInstance(protocol, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new GlobusSSLConfigurationException(e);
        } catch (NoSuchProviderException e) {
            throw new GlobusSSLConfigurationException(e);
        }
    }

    private SecureRandom loadSecureRandom() throws GlobusSSLConfigurationException {
        try {
            return secureRandomAlgorithm == null ? null : SecureRandom.getInstance(secureRandomAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new GlobusSSLConfigurationException(e);
        }
    }

    private KeyManager[] loadKeyManagers() throws GlobusSSLConfigurationException {

        try {
            KeyStore inputKeyStore = findKeyStore();
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(sslKeyManagerFactoryAlgorithm);
            keyManagerFactory.init(inputKeyStore, keyStorePassword == null ? null : keyStorePassword.toCharArray());
            return keyManagerFactory.getKeyManagers();
        } catch (KeyStoreException e) {
            throw new GlobusSSLConfigurationException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new GlobusSSLConfigurationException(e);
        } catch (UnrecoverableKeyException e) {
            throw new GlobusSSLConfigurationException(e);
        }
    }

    private CertStore findCertStore() throws GlobusSSLConfigurationException {
        CertStore certStoreToReturn = this.certStore;
        if (certStoreToReturn == null) {
            try {
                if (provider == null) {
                    certStoreToReturn = CertStore.getInstance(this.certStoreType, this.certStoreParams);
                } else {
                    certStoreToReturn = CertStore.getInstance(this.certStoreType, this.certStoreParams, provider);
                }
            } catch (InvalidAlgorithmParameterException e) {
                throw new GlobusSSLConfigurationException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new GlobusSSLConfigurationException(e);
            } catch (NoSuchProviderException e) {
                throw new GlobusSSLConfigurationException(e);
            }
        }
        return certStoreToReturn;
    }

    private KeyStore findTrustStore() throws GlobusSSLConfigurationException {
        KeyStore tmpTrustStore = this.trustStore;
        if(tmpTrustStore == null){
            try {
                PathMatchingResourcePatternResolver resourceResolver = new PathMatchingResourcePatternResolver();
                if (provider == null) {
                    tmpTrustStore = KeyStore.getInstance(this.trustStoreType);
                } else {
                    tmpTrustStore = KeyStore.getInstance(this.trustStoreType, this.provider);
                }
                InputStream keyStoreInput = resourceResolver.getResource(this.trustStoreLocation).getInputStream();
                tmpTrustStore.load(keyStoreInput, this.trustStorePassword == null ? null :
                        this.trustStorePassword.toCharArray());
            } catch (KeyStoreException e) {
                throw new GlobusSSLConfigurationException(e);
            } catch (IOException e) {
                throw new GlobusSSLConfigurationException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new GlobusSSLConfigurationException(e);
            } catch (CertificateException e) {
                throw new GlobusSSLConfigurationException(e);
            } catch (NoSuchProviderException e) {
                throw new GlobusSSLConfigurationException(e);
            }
        }
        return tmpTrustStore;
    }

    private KeyStore findKeyStore() throws GlobusSSLConfigurationException {
        KeyStore tmpKeyStore = this.keyStore;
        if (tmpKeyStore == null) {
            try {
                PathMatchingResourcePatternResolver resourceResolver = new PathMatchingResourcePatternResolver();
                if (provider == null) {
                    tmpKeyStore = KeyStore.getInstance(keyStoreType);
                } else {
                    tmpKeyStore = KeyStore.getInstance(keyStoreType, provider);
                }
                InputStream keyStoreInput = resourceResolver.getResource(this.keyStoreLocation).getInputStream();
                tmpKeyStore.load(keyStoreInput, this.keyStorePassword == null ? null :
                        this.keyStorePassword.toCharArray());
            } catch (KeyStoreException e) {
                throw new GlobusSSLConfigurationException(e);
            } catch (IOException e) {
                throw new GlobusSSLConfigurationException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new GlobusSSLConfigurationException(e);
            } catch (CertificateException e) {
                throw new GlobusSSLConfigurationException(e);
            } catch (NoSuchProviderException e) {
                throw new GlobusSSLConfigurationException(e);
            }
        }
        return tmpKeyStore;
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

    public KeyStore getTrustStore() {
        return trustStore;
    }

    public void setTrustStore(KeyStore trustStore) {
        this.trustStore = trustStore;
    }

    public CertStore getCertStore() {
        return certStore;
    }

    public void setCertStore(CertStore certStore) {
        this.certStore = certStore;
    }

    public SigningPolicyStore getPolicyStore() {
        return policyStore;
    }

    public void setPolicyStore(SigningPolicyStore policyStore) {
        this.policyStore = policyStore;
    }

    public boolean isRejectLimitProxy() {
        return rejectLimitProxy;
    }

    public void setRejectLimitProxy(boolean rejectLimitProxy) {
        this.rejectLimitProxy = rejectLimitProxy;
    }

    public Map<String, ProxyPolicyHandler> getHandlers() {
        return handlers;
    }

    public void setHandlers(Map<String, ProxyPolicyHandler> handlers) {
        this.handlers = handlers;
    }

    public String getKeyStoreLocation() {
        return keyStoreLocation;
    }

    public void setKeyStoreLocation(String keyStoreLocation) {
        this.keyStoreLocation = keyStoreLocation;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getTrustStoreType() {
        return trustStoreType;
    }

    public void setTrustStoreType(String trustStoreType) {
        this.trustStoreType = trustStoreType;
    }

    public String getTrustStoreLocation() {
        return trustStoreLocation;
    }

    public void setTrustStoreLocation(String trustStoreLocation) {
        this.trustStoreLocation = trustStoreLocation;
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }

    public String getCertStoreType() {
        return certStoreType;
    }

    public void setCertStoreType(String certStoreType) {
        this.certStoreType = certStoreType;
    }

    public CertStoreParameters getCertStoreParams() {
        return certStoreParams;
    }

    public void setCertStoreParams(CertStoreParameters certStoreParams) {
        this.certStoreParams = certStoreParams;
    }

    public String[] getEnabledCipherSuites() {
        return enabledCipherSuites;
    }

    public void setEnabledCipherSuites(String[] enabledCipherSuites) {
        this.enabledCipherSuites = enabledCipherSuites;
    }
}
