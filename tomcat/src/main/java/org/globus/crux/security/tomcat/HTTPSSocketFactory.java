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

package org.globus.crux.security.tomcat;

import org.apache.tomcat.util.net.ServerSocketFactory;
import org.globus.security.util.SSLConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 7, 2010
 * Time: 1:40:40 PM
 * To change this template use File | Settings | File Templates.
 */
public class HTTPSSocketFactory extends ServerSocketFactory {
    private SSLConfigurator config = new SSLConfigurator();
    private SSLServerSocketFactory delegate;
    private Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Flag to state that we require client authentication.
     */
    protected boolean requireClientAuth = false;

    /**
     * Flag to state that we would like client authentication.
     */
    protected boolean wantClientAuth = false;

    protected boolean allowUnsafeLegacyRenegotiation = false;


    private SSLServerSocketFactory getServerSocketFactory() throws IOException {
        if (delegate == null) {
            try {
                delegate = config.createServerFactory();
            } catch (Exception e) {
                logger.warn("Error creating server socket factory", e);
                throw new IOException(e.getMessage());
            }
        }
        return delegate;
    }

    public Socket acceptSocket(ServerSocket socket)
            throws IOException {
        SSLSocket asock = null;
        try {
            asock = (SSLSocket) socket.accept();
            configureClientAuth(asock);
        } catch (SSLException e) {
            throw new SocketException("SSL handshake error" + e.toString());
        }
        return asock;
    }

    @Override
    public ServerSocket createSocket(int i) throws IOException, InstantiationException {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public ServerSocket createSocket(int i, int i1) throws IOException, InstantiationException {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public ServerSocket createSocket(int i, int i1, InetAddress inetAddress)
            throws IOException, InstantiationException {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void handshake(Socket sock) throws IOException {
        if (sock instanceof SSLSocket) {
            ((SSLSocket) sock).startHandshake();

            if (!allowUnsafeLegacyRenegotiation) {
                // Prevent futher handshakes by removing all cipher suites
                ((SSLSocket) sock).setEnabledCipherSuites(new String[0]);
            }
        }
    }

    /**
     * Configure Client authentication for this version of JSSE.  The
     * JSSE included in Java 1.4 supports the 'want' value.  Prior
     * versions of JSSE will treat 'want' as 'false'.
     *
     * @param socket the SSLSocket
     */
    protected void configureClientAuth(SSLSocket socket) {
        // Per JavaDocs: SSLSockets returned from
        // SSLServerSocket.accept() inherit this setting.
    }


}
