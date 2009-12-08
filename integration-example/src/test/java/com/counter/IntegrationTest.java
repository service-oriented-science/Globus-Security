/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.counter;

import java.security.Security;

import org.globus.security.TestClient;
import org.globus.security.TestServer;
import org.globus.security.provider.GlobusProvider;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
@Test
public class IntegrationTest {
    TestServer server;

    static {
        Security.addProvider(new GlobusProvider());
    }

    @Parameters({"port", "policy_location", "key_store", "trust_store", "crl_trust_store", "key_password"})
    @Test
    public void testHello(int port, String policyLocation, String keyStore,
                      String trustStore, String crlTrustStore, String keyPassword) throws Exception{
        TestClient client = new TestClient();
        client.setPort(port);
        client.setPolicyLocation(policyLocation);
        client.setKeyStore(keyStore);
        client.setTrustStore(trustStore);
        client.setCrlTrustStore(crlTrustStore);
        client.setKeyPassword(keyPassword);
        assertEquals("hello", client.echo("hello"));
    }

    @Parameters({"port", "policy_location", "key_store", "trust_store", "crl_trust_store", "key_password"})
    @BeforeClass
    public void setup(int port, String policyLocation, String keyStore,
                      String trustStore, String crlTrustStore, String keyPassword) throws Exception {
        server = new TestServer();
        server.setPort(port);
        server.setPolicyLocation(policyLocation);
        server.setKeyStore(keyStore);
        server.setTrustStore(trustStore);
        server.setCrlTrustStore(crlTrustStore);
        server.setKeyPassword(keyPassword);
        server.init();
    }

    @AfterClass
    public void destroy() throws Exception{
        server.destroy();
    }
}
