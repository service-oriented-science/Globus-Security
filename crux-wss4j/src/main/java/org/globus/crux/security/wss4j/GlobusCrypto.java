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
package org.globus.crux.security.wss4j;

import java.security.cert.CertPathParameters;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.globus.security.X509ProxyCertPathParameters;
import org.globus.security.provider.X509ProxyCertPathValidator;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.CryptoBase;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class GlobusCrypto extends CryptoBase{
    public static final String SIGNING_POLICY_STORE_PARAMS = "org.globus.crux.security.wss4j.signingpolicyparams";
//    public static final String KEY

    public GlobusCrypto(Properties props){

    }

    @Override
    public boolean validateCertPath(X509Certificate[] certs) throws WSSecurityException {
        X509ProxyCertPathValidator validator = new X509ProxyCertPathValidator();
//        X509ProxyCertPathParameters params = new X509ProxyCertPathParameters()
//        validator.engineValidate()
        return super.validateCertPath(
                certs);    //CHANGEME To change body of overridden methods use File | Settings | File Templates.
    }

    @Override
    protected String getCryptoProvider() {
        return null;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public String getDefaultX509Alias() {
        return null;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }
}
