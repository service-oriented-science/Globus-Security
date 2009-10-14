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
package org.globus.security;

import org.globus.security.proxyExtension.ProxyPolicyHandler;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.KeyStore;
import java.security.cert.CertPathParameters;
import java.security.cert.CertStore;
import java.util.Map;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class X509ProxyCertPathParameters implements CertPathParameters {

    // For trusted CAs
    KeyStore keyStore;
    // For CRLs
    CertStore certStore;
    // For signing policy
    SigningPolicyStore policyStore;
    boolean rejectLimitedProxy;
    Map<String, ProxyPolicyHandler> handlers;

    // FIXME: we could add another constructor that takes trusted CA
    // certificate collection, CRL collcetion and signing policy collection,
    // but implementations that use this need to be modified to not expect
    // tores and thus refresh of credentials. One seamless way would be to
    // create corresponding store objects for the provided input in this
    // constructor and implementations can work without caring about how this
    // object was created. 
    public X509ProxyCertPathParameters(KeyStore keyStore_,
                                       CertStore certStore_,
                                       SigningPolicyStore policyStore_,
                                       boolean rejectLimitedProxy_) {
        this(keyStore_, certStore_, policyStore_, rejectLimitedProxy_, null);
    }



    public X509ProxyCertPathParameters(KeyStore keyStore_,
                                       CertStore certStore_,
                                       SigningPolicyStore policyStore_,
                                       boolean rejectLimitedProxy_,
                                       Map<String, ProxyPolicyHandler> handlers_) {

        if ((keyStore_ == null) ||
            (certStore_ == null) ||
            (policyStore_ == null)) {
            throw new IllegalArgumentException();
        }
        this.keyStore = keyStore_;
        this.certStore = certStore_;
        this.policyStore = policyStore_;
        this.rejectLimitedProxy = rejectLimitedProxy_;
        this.handlers = handlers_;
    }

    public KeyStore getKeyStore() {
        return this.keyStore;
    }

    public CertStore getCertStore() {
        return this.certStore;
    }

    public SigningPolicyStore getSigningPolicyStore() {
        return this.policyStore;
    }

    public boolean isRejectLimitedProxy() {
        return this.rejectLimitedProxy;
    }

    public Map<String, ProxyPolicyHandler> getPolicyHandlers() {
        return this.handlers;
    }

    /**
     * Makes a copy of this <code>CertPathParameters</code>. Changes to the copy
     * will not affect the original and vice versa.
     *
     * @return a copy of this <code>CertPathParameters</code>
     */
    public Object clone() {
        try {
            X509ProxyCertPathParameters clone = (X509ProxyCertPathParameters) super.clone();
            return clone;
        } catch (CloneNotSupportedException e) {
            throw new InternalError(e.toString());

        }        
    }
}
