package org.globus.security;

import java.io.File;
import java.security.Security;

import javax.net.ssl.SSLSocketFactory;

import org.globus.security.filestore.FileCertStoreParameters;
import org.globus.security.filestore.FileSigningPolicyStoreParameters;
import org.globus.security.provider.GlobusProvider;
import org.globus.security.util.SSLConfigurator;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;

import com.ecerami.wsdl.helloservice_wsdl.HelloPortType;
import com.ecerami.wsdl.helloservice_wsdl.HelloService;

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
        HelloService service =
                new HelloService(TestClient.class.getResource("/hello_world.wsdl"));
        HelloPortType port = service.getHelloPort();
        Client client = ClientProxy.getClient(port);
        HTTPConduit conduit = (HTTPConduit) client.getConduit();
        TLSClientParameters tlsParams = new TLSClientParameters();
        SSLConfigurator configurator = configure();
        SSLSocketFactory socketFactory = configurator.createFactory();
        tlsParams.setSSLSocketFactory(socketFactory);
        tlsParams.setDisableCNCheck(true);
        conduit.setTlsClientParameters(tlsParams);
        System.out.println(port.sayHello("hello"));
    }

    private static SSLConfigurator configure() {
        SSLConfigurator configurator = new SSLConfigurator();
        configurator.setKeyStoreType("JKS");
        configurator.setKeyStore(TestServer.KEY_STORE);
        configurator.setKeyPassword(TestServer.KEY_PASSWORD);
        configurator.setPassword(TestServer.KEY_PASSWORD);
        configurator.setProtocol("TLS");
        SigningPolicyStoreParameters spsParams =
                new FileSigningPolicyStoreParameters(
                        new String[]{new File(TestServer.POLICY_LOCATION).getAbsolutePath()});
        configurator.setSigningPolicyStoreParameters(spsParams);
        configurator.setTrustStoreType("JKS");
        configurator.setTrustStorePath(TestServer.TRUST_STORE);
        configurator.setTrustStorePassword(TestServer.KEY_PASSWORD);
        FileCertStoreParameters certStoreParams =
                new FileCertStoreParameters(new String[]{new File(TestServer.KEY_PASSWORD).getAbsolutePath()});
        configurator.setCertStoreParameters(certStoreParams);
        return configurator;
    }
}
