package org.globus.security;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.transport.http.HTTPConduit;
import org.globus.security.filestore.FileCertStoreParameters;
import org.globus.security.filestore.FileSigningPolicyStoreParameters;
import org.globus.security.provider.GlobusProvider;
import org.globus.security.sample.services.HelloWorldImpl;
import org.globus.security.util.SSLConfigurator;

import javax.net.ssl.SSLSocketFactory;
import java.io.File;


/**
 * Hello world!
 */
public class TestClient {

    private int port = 8443;
    private String policyLocation = TestServer.POLICY_LOCATION;
    private String keyStore = TestServer.KEY_STORE;
    private String trustStore = TestServer.TRUST_STORE;
    private String crlTrustStore = TestServer.CRL_TRUST_STORE;
    private String keyPassword = TestServer.KEY_PASSWORD;

    public TestClient() {
    }

    public void setPolicyLocation(String policyLocation) {
        this.policyLocation = policyLocation;
    }

    public void setKeyStore(String keyStore) {
        this.keyStore = keyStore;
    }

    public void setTrustStore(String trustStore) {
        this.trustStore = trustStore;
    }

    public void setCrlTrustStore(String crlTrustStore) {
        this.crlTrustStore = crlTrustStore;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String echo(String toSay) throws Exception {
        JaxWsProxyFactoryBean beanFac = new JaxWsProxyFactoryBean();
        beanFac.setServiceClass(HelloPortType.class);
        beanFac.setAddress("https://localhost:" + port + "/counter");
        HelloPortType service = (HelloPortType) beanFac.create();
        Client proxy = ClientProxy.getClient(service);
        HTTPConduit conduit = (HTTPConduit) proxy.getConduit();
        TLSClientParameters tlsParams = configureTLS();
        conduit.setTlsClientParameters(tlsParams);
        return service.sayHello(toSay);
    }


    private TLSClientParameters configureTLS() throws Exception {
        TLSClientParameters tlsParams = new TLSClientParameters();
        SSLConfigurator configurator = configure();
        SSLSocketFactory socketFactory = configurator.createFactory();
        tlsParams.setSSLSocketFactory(socketFactory);
        tlsParams.setDisableCNCheck(true);
        return tlsParams;
    }

    private SSLConfigurator configure() {
        SSLConfigurator configurator = new SSLConfigurator();
        configurator.setKeyStoreType("PEMFilebasedKeyStore");
        configurator.setKeyStore(keyStore);
//        configurator.setKeyStorePassword(TestServer.KEY_PASSWORD);
        configurator.setKeyPassword(TestServer.KEY_PASSWORD);
        configurator.setProtocol("TLS");
        SigningPolicyStoreParameters spsParams =
                new FileSigningPolicyStoreParameters(
                        new String[]{new File(policyLocation).getAbsolutePath()});
        configurator.setSigningPolicyStoreParameters(spsParams);
        configurator.setTrustStoreType("PEMFilebasedKeyStore");
        configurator.setTrustStorePath(trustStore);
        configurator.setTrustStorePassword(keyPassword);
        FileCertStoreParameters certStoreParams =
                new FileCertStoreParameters(new String[]{crlTrustStore});
        configurator.setCertStoreParameters(certStoreParams);
        return configurator;
    }
}
