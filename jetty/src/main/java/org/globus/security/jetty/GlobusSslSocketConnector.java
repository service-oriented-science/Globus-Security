package org.globus.security.jetty;

import org.globus.security.SigningPolicyStoreParameters;
import org.globus.security.util.SSLConfigurator;
import org.mortbay.jetty.security.SslSocketConnector;

import javax.net.ssl.SSLServerSocketFactory;
import java.security.cert.CertStoreParameters;

/**
 *
 */
public class GlobusSslSocketConnector extends SslSocketConnector {


    private SSLConfigurator sslConfigurator = new SSLConfigurator();

    @Override
    protected SSLServerSocketFactory createFactory() throws Exception {
        return sslConfigurator.createServerFactory();
    }

    public void setCertStoreParameters(CertStoreParameters certStoreParameters) {
        sslConfigurator.setCertStoreParameters(certStoreParameters);
    }

    public String getProvider() {
        return sslConfigurator.getProvider();
    }

    public void setProvider(String provider) {
        sslConfigurator.setProvider(provider);
    }

    public String getProtocol() {
        return sslConfigurator.getProtocol();
    }

    public void setProtocol(String protocol) {
        sslConfigurator.setProtocol(protocol);
    }

    public String getSecureRandomAlgorithm() {
        return sslConfigurator.getSecureRandomAlgorithm();
    }

    public void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
        sslConfigurator.setSecureRandomAlgorithm(secureRandomAlgorithm);
    }


    public void setSigningPolicyStoreParameters(SigningPolicyStoreParameters signingPolicyStoreParameters) {
        sslConfigurator.setSigningPolicyStoreParameters(signingPolicyStoreParameters);
    }


    public void setPassword(String password) {
        sslConfigurator.setPassword(password);
    }

    public String getSslKeyManagerFactoryAlgorithm() {
        return sslConfigurator.getSslKeyManagerFactoryAlgorithm();
    }

    public void setSslKeyManagerFactoryAlgorithm(String sslKeyManagerFactoryAlgorithm) {
        sslConfigurator.setSslKeyManagerFactoryAlgorithm(sslKeyManagerFactoryAlgorithm);
    }

    public void setKeyPassword(String keyPassword) {
        sslConfigurator.setKeyPassword(keyPassword);
    }

    public void setTrustStoreType(String trustStoreType) {
        sslConfigurator.setTrustStoreType(trustStoreType);
    }


    public void setTrustStore(String trustStorePath) {
        sslConfigurator.setTrustStorePath(trustStorePath);
    }


    public void setTrustStorePassword(String trustStorePassword) {
        sslConfigurator.setTrustStorePassword(trustStorePassword);
    }

    @Override
    public void setKeystore(String keystore) {
        sslConfigurator.setKeyStore(keystore);
    }

    @Override
    public void setTrustPassword(String password) {
        sslConfigurator.setTrustStorePassword(password);
    }

    @Override
    public void setKeystoreType(String keystoreType) {
        sslConfigurator.setKeyStoreType(keystoreType);
    }

    @Override
    public void setSslTrustManagerFactoryAlgorithm(String algorithm) {
        sslConfigurator.setSslTrustManagerFactoryAlgorithm(algorithm);
    }

    @Override
    public void setTruststore(String truststore) {
        sslConfigurator.setTrustStorePath(truststore);
    }

    @Override
    public void setTruststoreType(String truststoreType) {
        sslConfigurator.setTrustStoreType(truststoreType);
    }

    @Override
    public void setWantClientAuth(boolean wantClientAuth) {
        super.setWantClientAuth(wantClientAuth);    //To change body of overridden methods use File | Settings | File Templates.
    }

    @Override
    public void setHandshakeTimeout(int msec) {
        super.setHandshakeTimeout(msec);    //To change body of overridden methods use File | Settings | File Templates.
    }

    public void setSSLConfigurator(SSLConfigurator configurator){
        this.sslConfigurator = configurator;
    }
}
