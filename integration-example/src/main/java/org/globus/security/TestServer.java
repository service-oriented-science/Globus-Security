package org.globus.security;

import org.globus.security.filestore.FileCertStoreParameters;
import org.globus.security.filestore.FileSigningPolicyStoreParameters;
import org.globus.security.jetty.GlobusSslSocketConnector;
import org.globus.security.util.SSLConfigurator;
import org.globus.security.provider.GlobusProvider;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.webapp.WebAppContext;

import java.io.File;
import java.security.Security;


public class TestServer {
    public static final String POLICY_LOCATION = "./proxyProcessor/src/test/resources/validatorTest";
    public static final String KEY_STORE = "/Users/turtlebender/keystore.jks";
    public static final String TRUST_STORE = "/Users/turtlebender/cacerts.jks";
    public static final String KEY_PASSWORD = "password";
    public static final String WAR = "/Users/turtlebender/src/security/integration-example/target/integration-example.war";

    static {
        Security.addProvider(new GlobusProvider());
    }

    public static void main(String[] args) throws Exception {
        Server server = new Server();
        GlobusSslSocketConnector connector = new GlobusSslSocketConnector();
        SSLConfigurator configurator = configure();        
        connector.setSSLConfigurator(configurator);
        connector.setNeedClientAuth(true);
        connector.setPort(8443);
        WebAppContext context = new WebAppContext(WAR, "/");
        server.addHandler(context);
        server.addConnector(connector);
        server.start();
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
        configurator.setTrustStorePassword("password");
        FileCertStoreParameters certStoreParams =
                new FileCertStoreParameters(new String[]{new File(KEY_PASSWORD).getAbsolutePath()});
        configurator.setCertStoreParameters(certStoreParams);
        return configurator;
    }
}
