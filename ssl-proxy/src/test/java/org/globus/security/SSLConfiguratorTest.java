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

import org.globus.security.filestore.FileBasedKeyStoreParameters;
import org.globus.security.provider.FileBasedKeyStore;
import org.globus.security.provider.GlobusProvider;
import org.globus.security.resources.ResourceCertStoreParameters;
import org.globus.security.resources.ResourceSigningPolicyStore;
import org.globus.security.resources.ResourceSigningPolicyStoreParameters;
import org.globus.security.util.GlobusSSLConfigurationException;
import org.globus.security.util.SSLConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertStore;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.testng.Assert.assertEquals;

@Test
public class SSLConfiguratorTest {

    public static final String POLICY_LOCATION = "/Users/ranantha/.globus/certificates";
    //    public static final String KEY_STORE = "/keystore.jks";
    public static final String KEY_STORE = "/myKeystore";
    //    public static final String TRUST_STORE = "/cacerts.jks";
    public static final String TRUST_STORE = "/myTruststore";
    public static final String CRL_TRUST_STORE = "/Users/ranantha/.globus/certificates";
    public static final String KEY_PASSWORD = "password";

    public String policyLocation = POLICY_LOCATION;
    public String keyStore = KEY_STORE;
    public String trustStore = TRUST_STORE;
    public String crlTrustStore = CRL_TRUST_STORE;
    public String keyPassword = KEY_PASSWORD;


    private SSLSocket sslsocket;
    private SSLServerSocket serverSocket;
    private CountDownLatch latch = new CountDownLatch(1);
    private StringBuilder builder = new StringBuilder();

    @BeforeClass
    public void setup() throws Exception {
        Security.addProvider(new GlobusProvider());
    }

    @Test
    public void testConfig() throws Exception {

        SSLConfigurator config = new SSLConfigurator();

        ResourceCertStoreParameters params = new ResourceCertStoreParameters();
        config.setCertStoreParams(params);
        config.setCertStoreType(GlobusProvider.CERTSTORE_TYPE);

        config.setKeyStoreLocation("classpath:/mykeystore.properties");
        config.setKeyStorePassword(null);
        config.setKeyStoreType(GlobusProvider.KEYSTORE_TYPE);

        config.setTrustStoreLocation("classpath:/mytruststore.properties");
        config.setTrustStorePassword(null);
        config.setTrustStoreType(GlobusProvider.KEYSTORE_TYPE);

        ResourceSigningPolicyStoreParameters policyParams = new ResourceSigningPolicyStoreParameters(
                "classpath:/TestCA1.signing_policy");
        ResourceSigningPolicyStore policyStore = new ResourceSigningPolicyStore(policyParams);

        config.setPolicyStore(policyStore);

        serverSocket = startServer(config);
        latch.await();
        sslsocket = runClient(config);
        OutputStream outputstream = sslsocket.getOutputStream();
        OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
        BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);
        bufferedwriter.write("hello");
        bufferedwriter.flush();
        assertEquals(builder.toString().trim(), "hello");
    }

    private SSLSocket runClient(SSLConfigurator config) throws IOException, GlobusSSLConfigurationException {
        SSLSocketFactory sslsocketfactory = config.createFactory();

        return (SSLSocket) sslsocketfactory.createSocket("localhost", 9999);
    }

    @AfterClass
    public void stop() throws Exception {
        serverSocket.close();
        sslsocket.close();
    }

    Logger logger = LoggerFactory.getLogger(SSLConfiguratorTest.class);

    private SSLServerSocket startServer(SSLConfigurator config) throws GlobusSSLConfigurationException, IOException {
        SSLServerSocketFactory sslserversocketfactory = config.createServerFactory();
        final SSLServerSocket sslserversocket = (SSLServerSocket) sslserversocketfactory.createServerSocket(9999);

        ExecutorService executor = Executors.newFixedThreadPool(1);
        executor.execute(new Runnable() {
            /**
             * When an object implementing interface <code>Runnable</code> is used
             * to create a thread, starting the thread causes the object's
             * <code>run</code> method to be called in that separately executing
             * thread.
             * <p/>
             * The general contract of the method <code>run</code> is that it may
             * take any action whatsoever.
             *
             * @see Thread#run()
             */
            public void run() {
                latch.countDown();
                try {
                    SSLSocket sslsocket = (SSLSocket) sslserversocket.accept();
                    InputStream inputstream = sslsocket.getInputStream();
                    InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
                    BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
                    String line;
                    while ((line = bufferedreader.readLine()) != null) {
                        builder.append(line);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
        return sslserversocket;
    }
}
