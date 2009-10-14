package org.globus.security;

import org.globus.security.filestore.FileBasedKeyStoreParameters;
import org.globus.security.filestore.FileCertStoreParameters;
import org.globus.security.filestore.FileSigningPolicyStoreParameters;
import org.globus.security.jetty.GlobusSslSocketConnector;
import org.globus.security.provider.GlobusProvider;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.security.SslSocketConnector;

import java.io.File;
import java.security.Security;


public class IntegrationTest {    

    public void test() throws Exception {
        Server server = new Server();
        GlobusSslSocketConnector connector = new GlobusSslSocketConnector();
        connector.setKeystore("/Users/turtlebender/keystore.jks");
        connector.setKeyPassword("password");
        connector.setPassword("password");
        FileBasedKeyStoreParameters trustStoreParams =
                new FileBasedKeyStoreParameters(new String[]{new File("./src/test/resources/validatorTest").getAbsolutePath()},
                        "Users/turtlebender/certificates");
        connector.setTrustStoreParameters(trustStoreParams);
        FileCertStoreParameters certStoreParams =
                new FileCertStoreParameters(new String[]{new File("./src/test/resources/validatorTest").getAbsolutePath()});
        connector.setCertStoreParameters(certStoreParams);
        SigningPolicyStoreParameters spsParams =
                new FileSigningPolicyStoreParameters(new String[]{new File("./src/test/resources/validatorTest").getAbsolutePath()});
        connector.setSigningPolicyStoreParameters(spsParams);
        server.addConnector(connector);
        server.start();
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new GlobusProvider());
        IntegrationTest test = new IntegrationTest();
        test.test();
    }
}
