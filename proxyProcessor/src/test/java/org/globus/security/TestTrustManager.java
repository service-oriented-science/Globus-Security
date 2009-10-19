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

import org.globus.security.provider.TestProxyPathValidator;
import org.globus.security.proxyExtension.ProxyPolicyHandler;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.security.KeyStore;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * FILL ME
 * <p/>
 * // FIXME: separate this from proxy path validator test class.
 *
 * @author ranantha@mcs.anl.gov
 */
public class TestTrustManager extends TestProxyPathValidator {

    @BeforeClass
    public void setup() throws Exception {

        super.setup();
    }

    @Test
    public void validationTest() throws Exception {

        KeyStore keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[0]});
        TestCertParameters parameters =
            new TestCertParameters(null, this.crls);

        CertStore certStore =
            CertStore.getInstance("TestCertStore", parameters);
        TestPolicyStore policyStore =
            new TestPolicyStore((Map)null);
        TestPKITrustManager manager =
            new TestPKITrustManager(keyStore, certStore, policyStore, false,
                                    null);
        X509Certificate[] certChain =
            new X509Certificate[]{goodCertsArr[5], goodCertsArr[1],
                                  goodCertsArr[0]};
        manager.checkClientTrusted(certChain, "RSA");
        manager.checkServerTrusted(certChain, "RSA");
        CertPathValidatorResult result = manager.getValidationResult();
        assert (result != null);
        assert (result instanceof X509ProxyCertPathValidatorResult);
        assert (!((X509ProxyCertPathValidatorResult)result).isLimited());

        // FIXME: get accepted issuers and validate. Code patch needed from Tom.

        // FIXME: add a failure case

    }


    class TestPKITrustManager extends PKITrustManager {

        TestPKITrustManager(KeyStore keyStore, CertStore certStore,
                            SigningPolicyStore policyStore,
                            boolean rejectLimitedProxy,
                            Map<String, ProxyPolicyHandler> policyHandlers) {
            super(keyStore, certStore, policyStore, rejectLimitedProxy,
                  policyHandlers);
        }


        protected void initializeValidator(KeyStore keyStore,
                                           CertStore certStore,
                                           SigningPolicyStore policyStore,
                                           boolean rejectLimitedProxy,
                                           Map<String, ProxyPolicyHandler> policyHandlers) {

            this.parameters =
                new X509ProxyCertPathParameters(keyStore, certStore,
                                                policyStore,
                                                rejectLimitedProxy,
                                                policyHandlers);

            this.validator =
                new MockProxyCertPathValidator(false, false, false);
        }

    }
}
