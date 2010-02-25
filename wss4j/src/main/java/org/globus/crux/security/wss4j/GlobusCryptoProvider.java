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

package org.globus.crux.security.wss4j;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.CredentialException;
import org.apache.ws.security.components.crypto.CryptoBase;
import org.globus.security.SigningPolicyStore;
import org.globus.security.X509ProxyCertPathParameters;
import org.globus.security.provider.GlobusProvider;
import org.globus.security.provider.X509ProxyCertPathValidator;
import org.globus.security.stores.ResourceSigningPolicyStore;
import org.globus.security.stores.ResourceSigningPolicyStoreParameters;
import org.globus.security.util.GlobusSSLConfigurationException;
import org.globus.security.util.GlobusSSLHelper;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Properties;

/**
 * This is a Crypto provider for WSS4J which supports the validation of proxy certificates in addition to standard
 * certficates.  In addition this provider explicitly supports CRL's, Signing Policies and allows rejecting of limited
 * proxies.
 *
 * @version 1.0
 * @since 1.0
 */
public class GlobusCryptoProvider extends CryptoBase {

    public static final String SECURITY_PROVIDER = "org.globus.crux.security.crypto.security.provider";
    public static final String CREDENTIAL_STORE_TYPE = "org.globus.crux.security.crypto.credential.type";
    public static final String CREDENTIAL_STORE_FILE = "org.globus.crux.security.crypto.credential.file";
    public static final String CREDENTIAL_STORE_PASSWORD = "org.globus.crux.security.crypto.credential.password";

    public static final String TRUST_ANCHOR_STORE_TYPE = "org.globus.crux.security.crypto.trust.type";
    public static final String TRUST_ANCHOR_STORE_FILE = "org.globus.crux.security.crypto.trust.file";
    public static final String TRUST_ANCHOR_STORE_PASSWORD = "org.globus.crux.security.crypto.trust.password";

    public static final String CRL_STORE_CRL_PATTERN = "org.globus.crux.security.crypto.crl.crlPattern";

    public static final String POLICY_STORE_PATTERN = "org.globus.crux.security.crypto.policy.policyPattern";

    public static final String REJECT_LIMITED_PROXY = "org.globus.crux.security.crypto.rejectLimitedProxy";

    private static final String DEFAULT_SECURITY_PROVIDER = GlobusProvider.PROVIDER_NAME;

    private SigningPolicyStore policyStore;
    private boolean rejectLimitedProxy;
    private CertStore crlStore;
    private String cryptoProvider;

    /**
     * This allows providing a custom class loader to load the stores, etc
     *
     * @param properties The properties required to construct a certificate path validator.
     * @param loader     Custom class loader for loading stores.
     * @throws CredentialException if the credentials and certificates used are invalid
     * @throws IOException         if the credential, certificates, etc cannot be processed.
     */
    public GlobusCryptoProvider(Properties properties, ClassLoader loader) throws CredentialException, IOException {
        //TODO: provide support for the custom classloader
        init(properties);
    }

    /*
    This processes all of the properties and constructs the cert path validation parameters which are used for the
    actual validation of the certpath.
     */

    private void init(Properties props) throws CredentialException {
        cryptoProvider = props.getProperty("org.apache.ws.security.crypto.provider");
        
        String securityProvider = props.getProperty(SECURITY_PROVIDER);
        securityProvider = securityProvider == null ? DEFAULT_SECURITY_PROVIDER : securityProvider;
        try {
            //Configure the keystore to be used for signing
            this.keystore = GlobusSSLHelper.findCredentialStore(securityProvider,
                                props.getProperty(CREDENTIAL_STORE_TYPE), props.getProperty(CREDENTIAL_STORE_FILE),
                                props.getProperty(CREDENTIAL_STORE_PASSWORD));

            //Configure the certificate path validator
            this.cacerts = GlobusSSLHelper.buildTrustStore(securityProvider,
                    props.getProperty(TRUST_ANCHOR_STORE_TYPE), props.getProperty(TRUST_ANCHOR_STORE_FILE),
                    props.getProperty(TRUST_ANCHOR_STORE_PASSWORD));
            this.crlStore = GlobusSSLHelper.findCRLStore(props.getProperty(CRL_STORE_CRL_PATTERN));
            this.policyStore = new ResourceSigningPolicyStore(
                    new ResourceSigningPolicyStoreParameters(props.getProperty(POLICY_STORE_PATTERN)));
            this.rejectLimitedProxy = Boolean.parseBoolean(props.getProperty(REJECT_LIMITED_PROXY));
            //TODO: for now don't support ProxyPolicyHandlers  Add this later
//            if (handlers == null) {
//            parameters = new X509ProxyCertPathParameters(this.ca, crlStore, policyStore,
//                    rejectLimitProxy);
//            } else {
//                parameters = new X509ProxyCertPathParameters(credentialStore, crlStore, policyStore,
//                        rejectLimitProxy, handlers);
//            }

        } catch (GlobusSSLConfigurationException ex) {
            throw new CredentialException(WSSecurityException.FAILURE, "certpath", new Object[]{ex.getMessage()}, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new CredentialException(WSSecurityException.FAILURE, "certpath", new Object[]{ex.getMessage()}, ex);
        }
    }

    /**
     * Overridden because there's a bug in the base class where they don't use
     * the provider variant for the certificate validator.
     *
     * @param certs Certificate chain to validate
     * @return true if the certificate chain is valid, false otherwise
     * @throws org.apache.ws.security.WSSecurityException
     *
     */
    @Override
    public boolean validateCertPath(X509Certificate[] certs) throws WSSecurityException {
        try {
            CertPathParameters parameters = new X509ProxyCertPathParameters(this.cacerts, this.crlStore,
                    this.policyStore, this.rejectLimitedProxy);
            CertPath path = getCertificateFactory().generateCertPath(Arrays.asList(certs));
            new X509ProxyCertPathValidator().engineValidate(path, parameters);
            return true;
        } catch (CertificateException ex) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "certpath", new Object[]{ex.getMessage()}, ex);
        } catch (CertPathValidatorException ex) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "certpath", new Object[]{ex.getMessage()}, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "certpath", new Object[]{ex.getMessage()}, ex);
        }
    }

    /**
     * @return a crypto provider name.  This operation should
     *         return null if the default crypto provider should
     *         be used.
     */
    @Override
    protected String getCryptoProvider() {
        return cryptoProvider;
    }

    /**
     * Retrieves the alias name of the default certificate which has been
     * specified as a property. This should be the certificate that is used for
     * signature and encryption. This alias corresponds to the certificate that
     * should be used whenever KeyInfo is not present in a signed or
     * an encrypted message. May return null.
     *
     * @return alias name of the default X509 certificate.
     */
    public String getDefaultX509Alias() {
        //TODO:  Should this actually return something?
        return null;
    }
}

