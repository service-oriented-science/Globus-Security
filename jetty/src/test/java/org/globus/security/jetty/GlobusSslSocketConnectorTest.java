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

package org.globus.security.jetty;

import java.io.IOException;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.globus.crux.security.ClientTest;
import org.globus.security.provider.GlobusProvider;
import org.globus.security.stores.ResourceSigningPolicyStore;
import org.globus.security.stores.ResourceSigningPolicyStoreParameters;
import org.globus.security.util.SSLConfigurator;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.servlet.ServletHandler;
import org.mortbay.jetty.servlet.ServletHolder;

/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Feb 4, 2010 Time: 10:58:56
 * AM To change this template use File | Settings | File Templates.
 */
public class GlobusSslSocketConnectorTest extends ClientTest {

	private static Server server;

	@BeforeClass
	public static void setup() throws Exception {
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
		GlobusSslSocketConnector connector = new GlobusSslSocketConnector(config);
		server = new Server();
		connector.setPort(getPort());
		connector.setNeedClientAuth(true);

		server.addConnector(connector);
		ServletHandler handler = new ServletHandler();
		ServletHolder holder = new ServletHolder(new Servlet() {

			public void destroy() {
				// TODO Auto-generated method stub

			}

			public ServletConfig getServletConfig() {
				// TODO Auto-generated method stub
				return null;
			}

			public String getServletInfo() {
				// TODO Auto-generated method stub
				return null;
			}

			public void init(ServletConfig arg0) throws ServletException {
				// TODO Auto-generated method stub

			}

			public void service(ServletRequest arg0, ServletResponse arg1) throws ServletException, IOException {
				System.out.println("ServicingRequest");

			}

		});
		handler.addServletWithMapping(holder, "/");
		server.addHandler(handler);
		// server.addHandler(new JettySSLHandler());
		server.start();
	}

	@AfterClass
	public static void shutdown() throws Exception {
		server.stop();
	}
}
