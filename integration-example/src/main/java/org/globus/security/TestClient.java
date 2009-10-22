package org.globus.security;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.globus.security.filestore.FileCertStoreParameters;
import org.globus.security.filestore.FileSigningPolicyStoreParameters;
import org.globus.security.util.SSLConfigurator;
import org.globus.security.provider.GlobusProvider;

import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.security.Security;

import static org.globus.security.TestServer.*;

import com.ecerami.wsdl.helloservice.HelloPortType;
import com.ecerami.wsdl.helloservice.HelloService;


/**
 * Hello world!
 */
public class TestClient {
    static {
        Security.addProvider(new GlobusProvider());
    }

    public static void main(String[] args) throws Exception {
        HelloService service = new HelloService(new File("cxf-service/src/main/resources/hello_world.wsdl").toURI().toURL());
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
        configurator.setKeyStore(KEY_STORE);
        configurator.setKeyPassword(KEY_PASSWORD);
        configurator.setPassword(KEY_PASSWORD);
        configurator.setProtocol("TLS");
        SigningPolicyStoreParameters spsParams =
                new FileSigningPolicyStoreParameters(new String[]{new File(POLICY_LOCATION).getAbsolutePath()});
        configurator.setSigningPolicyStoreParameters(spsParams);
        configurator.setTrustStoreType("JKS");
        configurator.setTrustStorePath(TRUST_STORE);
        configurator.setTrustStorePassword(KEY_PASSWORD);
        FileCertStoreParameters certStoreParams =
                new FileCertStoreParameters(new String[]{new File(KEY_PASSWORD).getAbsolutePath()});
        configurator.setCertStoreParameters(certStoreParams);
        return configurator;
    }
}
