package org.globus.security;

import java.io.File;
import java.security.Security;
import java.util.Properties;

import org.globus.security.filestore.FileCertStoreParameters;
import org.globus.security.filestore.FileSigningPolicyStoreParameters;
import org.globus.security.jetty.GlobusSslSocketConnector;
import org.globus.security.provider.GlobusProvider;
import org.globus.security.util.SSLConfigurator;

import org.apache.cxf.transport.servlet.CXFServlet;

import org.mortbay.jetty.Server;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.ServletHolder;
import org.springframework.web.context.ContextLoaderListener;


public final class TestServer {
    public static final String POLICY_LOCATION = "/policies";
    public static final String KEY_STORE = "/keystore.jks";
    public static final String TRUST_STORE = "/cacerts.jks";
    public static final String KEY_PASSWORD = "password";
    private static int port = 8443;

    static {
        Security.addProvider(new GlobusProvider());
    }

    private TestServer() {
    }

    private static Context createWebContext() {
        Context context = new Context();
        ServletHolder servletHolder = new ServletHolder();
        servletHolder.setInitOrder(1);
        servletHolder.setServlet(new CXFServlet());
        servletHolder.setName("CXFServlet");
        servletHolder.setDisplayName("CXF Servlet");
        context.addServlet(servletHolder, "/");
        context.addEventListener(new ContextLoaderListener());
        Properties initParams = new Properties();
        initParams.put("contextConfigLocation", "classpath:/applicationContext.xml");
        context.setInitParams(initParams);
        return context;
    }

    public static void main(String[] args) throws Exception {
        Server server = new Server();
        server.addHandler(createWebContext());
        server.addConnector(createSSLConnector());
        server.start();
    }

    private static GlobusSslSocketConnector createSSLConnector() {
        GlobusSslSocketConnector connector = new GlobusSslSocketConnector();
        SSLConfigurator configurator = configure();
        connector.setSSLConfigurator(configurator);
        connector.setNeedClientAuth(true);
        connector.setPort(port);
        return connector;
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
