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
package org.globus.security.authorization.samples;

import java.security.Principal;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class IdentityAuthorization implements HostnameVerifier {

    private static Logger logger =
            LoggerFactory.getLogger(IdentityAuthorization.class.getName());

    private Principal acceptedPrincipal;

    public IdentityAuthorization(String acceptedDN) {

        if (acceptedDN == null) {
            throw new IllegalArgumentException("Accepted DN is required");
        }
        this.acceptedPrincipal = new X500Principal(acceptedDN);
    }

    public IdentityAuthorization(X500Principal acceptedPrincipal_) {

        if (acceptedPrincipal_ == null) {
            throw new IllegalArgumentException("Accepted principal is required");
        }

        this.acceptedPrincipal = acceptedPrincipal_;

    }

    public boolean verify(String s, SSLSession sslSession) {

        boolean authorized = false;
        try {
            Principal peerPrincipal = sslSession.getPeerPrincipal();
            if (this.acceptedPrincipal.equals(peerPrincipal)) {
                authorized = true;
            }
        } catch (SSLPeerUnverifiedException e) {
            logger.error("Unable to authorize peer", e);
        }

        return authorized;
    }
}
