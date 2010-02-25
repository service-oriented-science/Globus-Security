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

import java.security.InvalidAlgorithmParameterException;
import java.security.Security;
import java.util.Properties;

import javax.net.ssl.SSLSocketFactory;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.servlet.CXFServlet;
import org.globus.security.jetty.GlobusSslSocketConnector;
import org.globus.security.provider.GlobusProvider;
import org.globus.security.stores.ResourceSigningPolicyStore;
import org.globus.security.stores.ResourceSigningPolicyStoreParameters;
import org.globus.security.util.SSLConfigurator;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.ServletHolder;
import org.springframework.web.context.ContextLoaderListener;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Feb 9, 2010
 * Time: 2:19:41 PM
 * To change this template use File | Settings | File Templates.
 */
@Test
public class IntegrationTest {
    Server server;

    static {
        Security.addProvider(new GlobusProvider());
    }


    private Context createCXFContext() throws Exception {
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
        return context;
    }

    @BeforeClass
    public void setup() throws Exception {
        GlobusSslSocketConnector connector = getConnector();
        server = new Server();
        connector.setPort(12345);
        connector.setNeedClientAuth(true);
        server.addHandler(createCXFContext());
        server.addConnector(connector);
        server.start();
        System.out.println("connector = " + connector);
    }

    private GlobusSslSocketConnector getConnector() throws InvalidAlgorithmParameterException {
        SSLConfigurator config = new SSLConfigurator();
        config.setCrlLocationPattern(null);
        config.setCrlStoreType(GlobusProvider.CERTSTORE_TYPE);

        config.setCredentialStoreLocation("classpath:/mykeystore.properties");
        config.setCredentialStorePassword("password");
        config.setCredentialStoreType(GlobusProvider.KEYSTORE_TYPE);

        config.setTrustAnchorStoreLocation("classpath:/mytruststore.properties");
        config.setTrustAnchorStorePassword("password");
        config.setTrustAnchorStoreType(GlobusProvider.KEYSTORE_TYPE);

        ResourceSigningPolicyStoreParameters policyParams = new ResourceSigningPolicyStoreParameters(
                "classpath:/globus_crux_ca.signing_policy");
        ResourceSigningPolicyStore policyStore = new ResourceSigningPolicyStore(policyParams);

        config.setPolicyStore(policyStore);
        return new GlobusSslSocketConnector(config);
    }

    public void runClient() throws Exception {
        JaxWsProxyFactoryBean beanFac = new JaxWsProxyFactoryBean();
        beanFac.setServiceClass(HelloPortType.class);
        beanFac.setAddress("https://localhost:" + 12345 + "/counter");
        HelloPortType service = (HelloPortType) beanFac.create();
        Client proxy = ClientProxy.getClient(service);
        HTTPConduit conduit = (HTTPConduit) proxy.getConduit();
        TLSClientParameters tlsParams = configureTLS();
        conduit.setTlsClientParameters(tlsParams);
        service.sayHello("Tom");
    }

    private TLSClientParameters configureTLS() throws Exception {
        TLSClientParameters tlsParams = new TLSClientParameters();
        SSLConfigurator configurator = configure();
        SSLSocketFactory socketFactory = configurator.createFactory();
        tlsParams.setSSLSocketFactory(socketFactory);
        tlsParams.setDisableCNCheck(true);
        return tlsParams;
    }

    private SSLConfigurator configure() throws Exception{
        SSLConfigurator config = new SSLConfigurator();
        config.setCrlLocationPattern(null);
        config.setCrlStoreType(GlobusProvider.CERTSTORE_TYPE);

        config.setCredentialStoreLocation("classpath:/mykeystore.properties");
        config.setCredentialStorePassword("password");
        config.setCredentialStoreType(GlobusProvider.KEYSTORE_TYPE);

        config.setTrustAnchorStoreLocation("classpath:/mytruststore.properties");
        config.setTrustAnchorStorePassword("password");
        config.setTrustAnchorStoreType(GlobusProvider.KEYSTORE_TYPE);

        ResourceSigningPolicyStoreParameters policyParams = new ResourceSigningPolicyStoreParameters(
                "classpath:/globus_crux_ca.signing_policy");
        ResourceSigningPolicyStore policyStore = new ResourceSigningPolicyStore(policyParams);

        config.setPolicyStore(policyStore);
        return config;
    }

    @AfterClass
    public void shutdown() throws Exception {
        server.stop();
    }


}
