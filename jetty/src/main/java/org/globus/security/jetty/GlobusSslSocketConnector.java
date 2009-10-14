package org.globus.security.jetty;

import org.globus.security.SigningPolicyStoreParameters;
import org.globus.security.X509ProxyCertPathParameters;
import org.globus.security.filestore.FileBasedSigningPolicyStore;
import org.globus.security.provider.GlobusProvider;
import org.mortbay.jetty.security.SslSocketConnector;
import org.mortbay.resource.Resource;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;

/**
 *
 */
public class GlobusSslSocketConnector extends SslSocketConnector {

    //    private CertPathParameters certPathParameters;

    private CertStoreParameters certStoreParameters;
    private KeyStore.LoadStoreParameter trustStoreParameters;
//    private ManagerFactoryParameters managerFactoryParameters;
    private SigningPolicyStoreParameters signingPolicyStoreParameters;
    private String secureRandomAlgorithm;
    private String provider;
    private String keyStore;
    private String keystoreType = "JKS";
    private String trustStoreType = "PEMFilebasedKeyStore";
    private String protocol = "TLS";
    private String password;
    private String keyPassword;
    private String sslKeyManagerFactoryAlgorithm =
            Security.getProperty("ssl.KeyManagerFactory.algorithm") == null
                    ? "SunX509"
                    : Security.getProperty("ssl.KeyManagerFactory.algorithm");
    private String sslTrustManagerFactoryAlgorithm =
            Security.getProperty("ssl.TrustManagerFactory.algorithm") == null
                    ? "PKITrustManager"
                    : Security.getProperty("ssl.TrustManagerFactory.algorithm");


    @Override
    protected SSLServerSocketFactory createFactory() throws Exception {
        InputStream keystoreInputStream = null;

        if (keyStore != null)
            keystoreInputStream = Resource.newResource(keyStore).getInputStream();

        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        keyStore.load(keystoreInputStream, password == null ? null : password.toCharArray());


        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(sslKeyManagerFactoryAlgorithm);
        keyManagerFactory.init(keyStore,
                keyPassword == null
                        ? null
                        : keyPassword.toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();


        KeyStore trustStore = KeyStore.getInstance(trustStoreType);
//        trustStore.load(truststoreInputStream, trustPassword == null ? null : trustPassword.toString().toCharArray());
        trustStore.load(this.trustStoreParameters);

        CertStore certStore = CertStore.getInstance("X509ProxyFileStore", certStoreParameters);
        FileBasedSigningPolicyStore spStore = new FileBasedSigningPolicyStore(signingPolicyStoreParameters);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(this.sslTrustManagerFactoryAlgorithm);
        X509ProxyCertPathParameters parameters = new X509ProxyCertPathParameters(trustStore, certStore, spStore, false);
        tmf.init(new CertPathTrustManagerParameters(parameters));
        TrustManager[] trustManagers = tmf.getTrustManagers();

        SecureRandom secureRandom = secureRandomAlgorithm == null
                ? null
                : SecureRandom.getInstance(secureRandomAlgorithm);

        SSLContext context = provider == null
                ? SSLContext.getInstance(protocol)
                : SSLContext.getInstance(protocol, provider);

        context.init(keyManagers, trustManagers, secureRandom);

        return context.getServerSocketFactory();
    }

    public CertStoreParameters getCertStoreParameters() {
        return certStoreParameters;
    }

    public void setCertStoreParameters(CertStoreParameters certStoreParameters) {
        this.certStoreParameters = certStoreParameters;
    }

    public KeyStore.LoadStoreParameter getTrustStoreParameters() {
        return trustStoreParameters;
    }

    public void setTrustStoreParameters(KeyStore.LoadStoreParameter trustStoreParameters) {
        this.trustStoreParameters = trustStoreParameters;
    }


    public SigningPolicyStoreParameters getSigningPolicyStoreParameters() {
        return signingPolicyStoreParameters;
    }

    public void setSigningPolicyStoreParameters(SigningPolicyStoreParameters signingPolicyStoreParameters) {
        this.signingPolicyStoreParameters = signingPolicyStoreParameters;
    }

    public String getSecureRandomAlgorithm() {
        return secureRandomAlgorithm;
    }

    public void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
        this.secureRandomAlgorithm = secureRandomAlgorithm;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(String keyStore) {
        this.keyStore = keyStore;
    }

    public String getKeystoreType() {
        return keystoreType;
    }

    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }

    public String getTrustStoreType() {
        return trustStoreType;
    }

    public void setTrustStoreType(String trustStoreType) {
        this.trustStoreType = trustStoreType;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getKeyPassword() {
        return keyPassword;
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

    public String getSslTrustManagerFactoryAlgorithm() {
        return sslTrustManagerFactoryAlgorithm;
    }

    public void setSslTrustManagerFactoryAlgorithm(String sslTrustManagerFactoryAlgorithm) {
        this.sslTrustManagerFactoryAlgorithm = sslTrustManagerFactoryAlgorithm;
    }
}
