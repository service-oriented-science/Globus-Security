/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.globus.security;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.servlet.CXFServlet;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.security.SslSocketConnector;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.ServletHolder;
import org.springframework.web.context.ContextLoaderListener;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 27, 2010
 * Time: 4:00:20 PM
 * To change this template use File | Settings | File Templates.
 */
public class SSLTest {

    public static void main(String[] args) throws Exception {
        Server server = new Server();
        Context context = new Context();
        ServletHolder servletHolder = new ServletHolder();
        servletHolder.setInitOrder(1);
        servletHolder.setServlet(new CXFServlet());
        servletHolder.setName("CXFServlet");
        servletHolder.setDisplayName("CXF Servlet");
        context.addServlet(servletHolder, "/counter");
        context.addEventListener(new ContextLoaderListener());
        Properties initParams = new Properties();
        initParams.put("contextConfigLocation", "classpath:/applicationContext.xml");
        context.setInitParams(initParams);
        server.addHandler(context);
        server.addConnector(createSSLConnector());
        server.start();
        configureClient();
    }

    private static String configureClient() throws Exception {
        JaxWsProxyFactoryBean beanFac = new JaxWsProxyFactoryBean();
        beanFac.setServiceClass(HelloPortType.class);
        beanFac.setAddress("https://localhost:55433/counter");
        HelloPortType service = (HelloPortType) beanFac.create();
        Client proxy = ClientProxy.getClient(service);
        HTTPConduit conduit = (HTTPConduit) proxy.getConduit();
        TLSClientParameters tlsParams = configureTLS();
        conduit.setTlsClientParameters(tlsParams);
        return service.sayHello("hello");
    }

    private static TLSClientParameters configureTLS() throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(SSLTest.class.getResourceAsStream("/client-keystore.jks"), "password".toCharArray());

        TLSClientParameters tlsParams = new TLSClientParameters();
        tlsParams.setDisableCNCheck(true);
        tlsParams.setKeyManagers(getKeyManagers(keystore));
        tlsParams.setTrustManagers(getTrustManagers(keystore));
        return tlsParams;
    }

    private static TrustManager[] getTrustManagers(KeyStore keystore) throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keystore);
        return tmf.getTrustManagers();
    }


    private static KeyManager[] getKeyManagers(KeyStore keystore) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keystore, "password".toCharArray());
        return kmf.getKeyManagers();
    }

    public static SslSocketConnector createSSLConnector() {
        SslSocketConnector connector = new SslSocketConnector();
        connector.setPort(55433);
        connector.setKeystore(SSLTest.class.getResource("/keystore.jks").toExternalForm());
        connector.setKeyPassword("password");
        connector.setTruststore(SSLTest.class.getResource("/keystore.jks").toExternalForm());
        connector.setTrustPassword("password");
        connector.setPassword("password");
        connector.setWantClientAuth(true);
        connector.setProtocol("TLS");
        return connector;
    }
}
