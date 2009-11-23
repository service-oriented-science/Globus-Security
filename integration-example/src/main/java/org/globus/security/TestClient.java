package org.globus.security;

import java.io.File;
import java.security.Security;

import javax.net.ssl.SSLSocketFactory;

import org.globus.hello.HelloPortType;
import org.globus.security.filestore.FileCertStoreParameters;
import org.globus.security.filestore.FileSigningPolicyStoreParameters;
import org.globus.security.provider.GlobusProvider;
import org.globus.security.util.SSLConfigurator;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.frontend.ClientProxyFactoryBean;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.transport.http.HTTPConduit;


/**
 * Hello world!
 */
public final class TestClient {
    static {
        Security.addProvider(new GlobusProvider());
    }

    private TestClient() {
    }

    public static void main(String[] args) throws Exception {
        JaxWsProxyFactoryBean beanFac = new JaxWsProxyFactoryBean();
        beanFac.setServiceClass(HelloPortType.class);
        beanFac.setAddress("https://localhost:8443/counter");
        HelloPortType service = (HelloPortType) beanFac.create();
        Client proxy = ClientProxy.getClient(service);
        HTTPConduit conduit = (HTTPConduit) proxy.getConduit();
        TLSClientParameters tlsParams = configureTLS();
        conduit.setTlsClientParameters(tlsParams);
        System.out.println(service.sayHello("hello"));
    }

    private static TLSClientParameters configureTLS() throws Exception {
        TLSClientParameters tlsParams = new TLSClientParameters();
        SSLConfigurator configurator = configure();
        SSLSocketFactory socketFactory = configurator.createFactory();
        tlsParams.setSSLSocketFactory(socketFactory);
        tlsParams.setDisableCNCheck(true);
        return tlsParams;
    }

    private static SSLConfigurator configure() {
        SSLConfigurator configurator = new SSLConfigurator();
        configurator.setKeyStoreType("PEMFilebasedKeyStore");
        configurator.setKeyStore(TestServer.KEY_STORE);
        configurator.setKeyPassword(TestServer.KEY_PASSWORD);
        configurator.setPassword(TestServer.KEY_PASSWORD);
        configurator.setProtocol("TLS");
        SigningPolicyStoreParameters spsParams =
                new FileSigningPolicyStoreParameters(
                        new String[]{new File(TestServer.POLICY_LOCATION).getAbsolutePath()});
        configurator.setSigningPolicyStoreParameters(spsParams);
        configurator.setTrustStoreType("PEMFilebasedKeyStore");
        configurator.setTrustStorePath(TestServer.TRUST_STORE);
        configurator.setTrustStorePassword(TestServer.KEY_PASSWORD);
        FileCertStoreParameters certStoreParams =
                new FileCertStoreParameters(new String[]{new File(TestServer.KEY_PASSWORD).getAbsolutePath()});
        configurator.setCertStoreParameters(certStoreParams);
        return configurator;
    }
}
