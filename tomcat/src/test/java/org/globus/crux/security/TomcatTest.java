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

package org.globus.crux.security;

import org.apache.catalina.Context;
import org.apache.catalina.Engine;
import org.apache.catalina.Host;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Embedded;
import org.globus.crux.security.tomcat.GlobusSSLSocketFactory;
import org.globus.crux.security.util.FileSetupUtil;
import org.globus.security.provider.GlobusProvider;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.security.Security;

/**
 * This test embeds a Tomcat server with our test credentials and policies.  It then tests two clients, one with
 * valid credentials, one with invalid credentials.
 *
 * @version 1.0
 * @since 1.0
 */
@Test
public class TomcatTest extends ClientTest {

    private Embedded embedded;
    FileSetupUtil validCert;
    FileSetupUtil validKey;

    static {
        Security.addProvider(new GlobusProvider());
    }

    /**
     * Create and start the embedded tomcat server.
     *
     * @throws Exception If there is an error creating the server.
     */
    @BeforeClass
    public void setup() throws Exception {
        embedded = new Embedded();
        Engine engine = embedded.createEngine();
        engine.setName("Catalina");
        engine.setDefaultHost("localhost");

        Host host = embedded.createHost("localhost", ".");
        engine.addChild(host);

        Context context = embedded.createContext("", "");
        host.addChild(context);
        embedded.addEngine(engine);

        Connector connector = embedded.createConnector("localhost", 5082, false);
        connector.setScheme("https");
        connector.setAttribute("socketFactory", GlobusSSLSocketFactory.class.getCanonicalName());
        validKey = new FileSetupUtil("mykeystore.properties");
        validKey.copyFileToTemp();
        connector.setAttribute("keystoreFile", validKey.getTempFile().getAbsolutePath());
        connector.setAttribute("keystoreType", GlobusProvider.KEYSTORE_TYPE);
        connector.setAttribute("keystorePassword", "password");
        validCert = new FileSetupUtil("mytruststore.properties");
        validCert.copyFileToTemp();
        connector.setAttribute("truststoreFile", validCert.getTempFile().getAbsolutePath());
        connector.setAttribute("truststoreType", GlobusProvider.KEYSTORE_TYPE);
        connector.setAttribute("truststorePassword", "password");
        connector.setAttribute("signingPolicyLocation", "classpath:/globus_crux_ca.signing_policy");
        connector.setAttribute("crlLocation", "");
        connector.setAttribute("clientAuth", "true");
        embedded.addConnector(connector);
        embedded.start();
    }

    /**
     * Stop the embedded tomcat server.
     *
     * @throws Exception If an error is thrown while stopping the server.
     */
    @AfterClass
    public void stop() throws Exception {
        embedded.stop();
        validKey.deleteFile();
        validCert.deleteFile();
    }


    /**
     * Test client with invalid credentials.
     *
     * @throws Exception This should happen.
     */
    @Override
    public void testInvalid() throws Exception {
        super.testInvalid();    //To change body of overridden methods use File | Settings | File Templates.
    }
}
