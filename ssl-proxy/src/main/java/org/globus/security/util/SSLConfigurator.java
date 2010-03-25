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

package org.globus.security.util;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.globus.security.SigningPolicyStore;
import org.globus.security.X509ProxyCertPathParameters;
import org.globus.security.provider.PKITrustManager;
import org.globus.security.provider.X509ProxyCertPathValidator;
import org.globus.security.proxyExtension.ProxyPolicyHandler;

/**
 * This class is used to configure and create SSL socket factories. The
 * factories can either be built by setting the credentialStore, crlStore,
 * trustAnchorStore and policyStore directly, or it can use the java security
 * SPI mechanism. This is the simplest way to configure the globus ssl support.
 * 
 * @version ${version}
 * @since 1.0
 */
public class SSLConfigurator {

	private String provider;
	private String protocol = "TLS";
	private String secureRandomAlgorithm;

	private KeyStore credentialStore;
	private KeyStore trustAnchorStore;
	private CertStore crlStore;

	private SigningPolicyStore policyStore;

	private boolean rejectLimitProxy;
	private Map<String, ProxyPolicyHandler> handlers;

	private String trustAnchorStoreType;
	private String trustAnchorStoreLocation;
	private String trustAnchorStorePassword;

	private String credentialStoreType;
	private String credentialStoreLocation;
	private String credentialStorePassword;

	private String crlStoreType;
	private String crlLocationPattern;
	private SSLContext sslContext;

	private String sslKeyManagerFactoryAlgorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm") == null ? "SunX509"
			: Security.getProperty("ssl.KeyManagerFactory.algorithm");

	/**
	 * Create an SSLSocketFactory based on the configured stores.
	 * 
	 * @return A configured SSLSocketFactory
	 * @throws GlobusSSLConfigurationException
	 *             If we fail to create the socketFactory.
	 */
	public SSLSocketFactory createFactory() throws GlobusSSLConfigurationException {		
		return getSSLContext().getSocketFactory();
	}

	/**
	 * Create an SSLContext based on the configured stores.
	 * 
	 * @return A configured SSLContext.
	 * @throws GlobusSSLConfigurationException
	 *             If we fail to create the context.
	 */
	public SSLContext getSSLContext() throws GlobusSSLConfigurationException {
		if(sslContext == null){
			configureContext();
		}
		return this.sslContext;
	}

	/**
	 * Create an SSLServerSocketFactory based on the configured stores.
	 * 
	 * @return A configured SSLServerSocketFactory
	 * @throws GlobusSSLConfigurationException
	 *             If we fail to create the server socket factory.
	 */
	public SSLServerSocketFactory createServerFactory() throws GlobusSSLConfigurationException {
		SSLContext context = getSSLContext();
		return context.getServerSocketFactory();
	}

	private void configureContext() throws GlobusSSLConfigurationException {

		X509ProxyCertPathParameters parameters = getCertPathParameters();

		TrustManager trustManager = new PKITrustManager(new X509ProxyCertPathValidator(), parameters);

		TrustManager[] trustManagers = new TrustManager[] { trustManager };

		KeyManager[] keyManagers = loadKeyManagers();

		SecureRandom secureRandom = loadSecureRandom();

		sslContext = loadSSLContext();

		try {
			sslContext.init(keyManagers, trustManagers, secureRandom);
		} catch (KeyManagementException e) {
			throw new GlobusSSLConfigurationException(e);
		}

	}

	private X509ProxyCertPathParameters getCertPathParameters() throws GlobusSSLConfigurationException {
		X509ProxyCertPathParameters parameters;
		KeyStore inputTrustStore = GlobusSSLHelper.buildTrustStore(this.provider, this.trustAnchorStoreType,
				this.trustAnchorStoreLocation, this.trustAnchorStorePassword);
		CertStore inputCertStore = GlobusSSLHelper.findCRLStore(this.crlLocationPattern);
		if (handlers == null) {
			parameters = new X509ProxyCertPathParameters(inputTrustStore, inputCertStore, this.policyStore,
					this.rejectLimitProxy);
		} else {
			parameters = new X509ProxyCertPathParameters(inputTrustStore, inputCertStore, this.policyStore,
					this.rejectLimitProxy, handlers);
		}
		return parameters;
	}

	private SSLContext loadSSLContext() throws GlobusSSLConfigurationException {
		try {
			return provider == null ? SSLContext.getInstance(protocol) : SSLContext.getInstance(protocol, provider);
		} catch (NoSuchAlgorithmException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (NoSuchProviderException e) {
			throw new GlobusSSLConfigurationException(e);
		}
	}

	private SecureRandom loadSecureRandom() throws GlobusSSLConfigurationException {
		try {
			return secureRandomAlgorithm == null ? null : SecureRandom.getInstance(secureRandomAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new GlobusSSLConfigurationException(e);
		}
	}

	private KeyManager[] loadKeyManagers() throws GlobusSSLConfigurationException {
		try {
			KeyStore inputKeyStore = GlobusSSLHelper.findCredentialStore(this.provider, this.credentialStoreType,
					this.credentialStoreLocation, this.credentialStorePassword);
			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(sslKeyManagerFactoryAlgorithm);
			keyManagerFactory.init(inputKeyStore, credentialStorePassword == null ? null : credentialStorePassword
					.toCharArray());
			return keyManagerFactory.getKeyManagers();
		} catch (KeyStoreException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new GlobusSSLConfigurationException(e);
		} catch (UnrecoverableKeyException e) {
			throw new GlobusSSLConfigurationException(e);
		}
	}

	public String getProvider() {
		return provider;
	}

	public void setProvider(String provider) {
		this.provider = provider;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public String getSecureRandomAlgorithm() {
		return secureRandomAlgorithm;
	}

	public void setSecureRandomAlgorithm(String secureRandomAlgorithm) {
		this.secureRandomAlgorithm = secureRandomAlgorithm;
	}

	public String getCredentialStorePassword() {
		return credentialStorePassword;
	}

	public void setCredentialStorePassword(String credentialStorePassword) {
		this.credentialStorePassword = credentialStorePassword;
	}

	public KeyStore getTrustAnchorStore() {
		return trustAnchorStore;
	}

	public void setTrustAnchorStore(KeyStore trustAnchorStore) {
		this.trustAnchorStore = trustAnchorStore;
	}

	public CertStore getCrlStore() {
		return crlStore;
	}

	public void setCrlStore(CertStore crlStore) {
		this.crlStore = crlStore;
	}

	public SigningPolicyStore getPolicyStore() {
		return policyStore;
	}

	public void setPolicyStore(SigningPolicyStore policyStore) {
		this.policyStore = policyStore;
	}

	public boolean isRejectLimitProxy() {
		return rejectLimitProxy;
	}

	public void setRejectLimitProxy(boolean rejectLimitProxy) {
		this.rejectLimitProxy = rejectLimitProxy;
	}

	public Map<String, ProxyPolicyHandler> getHandlers() {
		return handlers;
	}

	public void setHandlers(Map<String, ProxyPolicyHandler> handlers) {
		this.handlers = handlers;
	}

	public String getCredentialStoreLocation() {
		return credentialStoreLocation;
	}

	public void setCredentialStoreLocation(String credentialStoreLocation) {
		this.credentialStoreLocation = credentialStoreLocation;
	}

	public String getCredentialStoreType() {
		return credentialStoreType;
	}

	public void setCredentialStoreType(String credentialStoreType) {
		this.credentialStoreType = credentialStoreType;
	}

	public String getTrustAnchorStoreType() {
		return trustAnchorStoreType;
	}

	public void setTrustAnchorStoreType(String trustAnchorStoreType) {
		this.trustAnchorStoreType = trustAnchorStoreType;
	}

	public String getTrustAnchorStoreLocation() {
		return trustAnchorStoreLocation;
	}

	public void setTrustAnchorStoreLocation(String trustAnchorStoreLocation) {
		this.trustAnchorStoreLocation = trustAnchorStoreLocation;
	}

	public String getTrustAnchorStorePassword() {
		return trustAnchorStorePassword;
	}

	public void setTrustAnchorStorePassword(String trustAnchorStorePassword) {
		this.trustAnchorStorePassword = trustAnchorStorePassword;
	}

	public String getCrlStoreType() {
		return crlStoreType;
	}

	public void setCrlStoreType(String crlStoreType) {
		this.crlStoreType = crlStoreType;
	}

	public String getCrlLocationPattern() {
		return crlLocationPattern;
	}

	public void setCrlLocationPattern(String crlLocationPattern) {
		this.crlLocationPattern = crlLocationPattern;
	}

	public KeyStore getCredentialStore() {
		return credentialStore;
	}

	public void setCredentialStore(KeyStore credentialStore) {
		this.credentialStore = credentialStore;
	}
}
