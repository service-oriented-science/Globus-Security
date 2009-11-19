package org.globus.security.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.globus.security.SigningPolicyStoreParameters;
import org.globus.security.X509ProxyCertPathParameters;
import org.globus.security.filestore.FileBasedSigningPolicyStore;
import org.globus.security.provider.PKITrustManager;
import org.globus.security.provider.X509ProxyCertPathValidator;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Oct 15, 2009
 * Time: 7:34:57 PM
 * To change this template use File | Settings | File Templates.
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
    private String password;
    private String keyPassword;
    private String sslKeyManagerFactoryAlgorithm =
            Security.getProperty("ssl.KeyManagerFactory.algorithm") == null ? "SunX509" : Security.getProperty(
                    "ssl.KeyManagerFactory.algorithm"); // cert algorithm;
    private String trustStoreType = "PEMFilebasedKeyStore";
    private KeyStore.LoadStoreParameter trustStoreParameters;
    private String trustStorePath;
    private String trustStorePassword;
    private String certStoreType = "X509ProxyFileStore";

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

        CertStore certStore = CertStore.getInstance("X509ProxyFileStore", certStoreParameters);

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
    private TrustManager[] loadTrustManagers(KeyStore trustStore, CertStore certStore) throws InvalidAlgorithmParameterException {
        FileBasedSigningPolicyStore spStore = new FileBasedSigningPolicyStore(signingPolicyStoreParameters);
        X509ProxyCertPathValidator validator = new X509ProxyCertPathValidator();
        X509ProxyCertPathParameters parameters = new X509ProxyCertPathParameters(trustStore, certStore, spStore, false);
        TrustManager tm = new PKITrustManager(validator, parameters);
        return new TrustManager[]{tm};
    }

    private KeyManager[] loadKeyManagers() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        InputStream keystoreInputStream = null;

        if (keyStore != null) {
            keystoreInputStream = getResource(keyStore);
        }


        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(keystoreInputStream, password == null ? null : password.toCharArray());


        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(sslKeyManagerFactoryAlgorithm);
        keyManagerFactory.init(keyStore,
                keyPassword == null
                        ? null
                        : keyPassword.toCharArray());
        return keyManagerFactory.getKeyManagers();
    }

    private KeyStore loadTrustStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore trustStore = KeyStore.getInstance(trustStoreType);
        if (trustStoreParameters == null) {
            if (this.trustStorePath == null || this.trustStorePassword == null) {
                this.trustStorePath = this.keyStore;
                this.trustStorePassword = this.keyPassword;
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
                is = getClass().getResource(source).openStream();
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

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSslKeyManagerFactoryAlgorithm() {
        return sslKeyManagerFactoryAlgorithm;
    }

    public void setSslKeyManagerFactoryAlgorithm(String sslKeyManagerFactoryAlgorithm) {
        this.sslKeyManagerFactoryAlgorithm = sslKeyManagerFactoryAlgorithm;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
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