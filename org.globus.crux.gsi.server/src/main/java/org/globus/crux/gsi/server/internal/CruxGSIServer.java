package org.globus.crux.gsi.server.internal;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Properties;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.globus.crux.jsse.SSLConfigurator;
import org.globus.security.provider.GlobusProvider;
import org.globus.security.stores.ResourceSigningPolicyStore;
import org.globus.security.stores.ResourceSigningPolicyStoreParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CruxGSIServer {
	private Server server;
	private int port;
	private String proxyLocation;
	private String credentialLocation;
	private String certificateLocation;
	private String defaultTrustCertDirectory;
	private String trustStoreDirectories;
	private String signingPolicyStoreLocation;
	private String crlStoreLocation;
	private boolean rejectLimitedProxy;
	private String keyStoreType;
	private String keyStoreLocation;
	private String keyStorePassword;
	private String trustStoreType;
	private String trustStoreLocation;
	private String trustStorePassword;
	private Logger logger = LoggerFactory.getLogger(getClass());

	public void setCrlStoreLocation(String crlStoreLocation) {
		this.crlStoreLocation = crlStoreLocation;
	}

	private int getPort() {
		return 55555;
	}

	public Server getServer() {
		return this.server;
	}

	private KeyStore getKeyStore() throws KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException {
		KeyStore store = null;
		if (this.proxyLocation != null && this.proxyLocation.length() > 0) {
			logger.trace("loading proxy");
			store = KeyStore.getInstance(GlobusProvider.KEYSTORE_TYPE);
			Properties props = new Properties();
			props.put("proxyFilename", this.proxyLocation);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			props.store(baos, "");
			ByteArrayInputStream bais = new ByteArrayInputStream(baos
					.toByteArray());
			store.load(bais, "".toCharArray());

		} else if (this.certificateLocation != null
				&& this.certificateLocation.length() > 0
				&& this.credentialLocation != null
				&& this.credentialLocation.length() > 0) {
			logger.trace("loading cert/key");
			store = KeyStore.getInstance(GlobusProvider.KEYSTORE_TYPE);
			Properties props = new Properties();
			props.put("certificateFilename", this.certificateLocation);
			props.put("keyFilename", this.credentialLocation);
			logger.trace("loading keyStore with certificate: {} and key: {}",
					this.certificateLocation, this.credentialLocation);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			props.store(baos, "");
			ByteArrayInputStream bais = new ByteArrayInputStream(baos
					.toByteArray());
			store.load(bais, "".toCharArray());
		}
		return store;
	}

	public void init() throws Exception {
		SSLConfigurator config = new SSLConfigurator();
		config.setCrlLocationPattern(null);
		config.setCrlStoreType(GlobusProvider.CERTSTORE_TYPE);

		KeyStore store = getKeyStore();
		if (store != null) {
			config.setCredentialStore(store);
		} else {
			config.setCredentialStoreLocation(this.keyStoreLocation);
			config.setCredentialStorePassword(this.keyStorePassword);
			config.setCredentialStoreType(this.keyStoreType);
		}
		logger.trace("Finished loading keystore");
		if (this.trustStoreDirectories != null
				&& this.trustStoreDirectories.length() > 0
				&& this.defaultTrustCertDirectory != null
				&& this.defaultTrustCertDirectory.length() > 0) {
			logger.trace("Loading trustStore with full constructor");
			store = KeyStore.getInstance("PEMFilebasedKeyStore");
			Properties props = new Properties();
			props.put("directory_list", this.trustStoreDirectories);
			props.put("default_directory", this.defaultTrustCertDirectory);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			props.store(baos, "");
			ByteArrayInputStream bais = new ByteArrayInputStream(baos
					.toByteArray());
			store.load(bais, "".toCharArray());
			config.setTrustAnchorStore(store);
			logger.trace("Null TrustStore: " + (store == null));
		} else if (this.trustStoreDirectories != null
				&& this.trustStoreDirectories.length() > 0) {
			logger.trace("Loading trustStore with partial constructor");
			store = KeyStore.getInstance("PEMFilebasedKeyStore");
			Properties props = new Properties();
			props.put("directory_list", this.trustStoreDirectories);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			props.store(baos, "");
			ByteArrayInputStream bais = new ByteArrayInputStream(baos
					.toByteArray());
			store.load(bais, "".toCharArray());
			config.setTrustAnchorStore(store);
			logger.trace("Null TrustStore: " + (store == null));
		} else {
			logger.trace("loading default trust store");
			config.setTrustAnchorStoreLocation(this.trustStoreLocation);
			config.setTrustAnchorStorePassword(this.trustStorePassword);
			config.setTrustAnchorStoreType(this.trustStoreType);
		}
		if (this.signingPolicyStoreLocation != null
				&& this.signingPolicyStoreLocation.length() > 0) {
			logger.trace("Loading policy store");
			ResourceSigningPolicyStoreParameters policyParams = new ResourceSigningPolicyStoreParameters(
					this.signingPolicyStoreLocation);
			ResourceSigningPolicyStore policyStore = new ResourceSigningPolicyStore(
					policyParams);
			config.setPolicyStore(policyStore);
		}
		logger.trace("create connector");
		// GlobusSslSocketConnector connector = new GlobusSslSocketConnector(
		// config);
		server = new Server();
		// connector.setPort(getPort());
		// connector.setNeedClientAuth(true);
		SelectChannelConnector connector = new SelectChannelConnector();
		connector.setHost("127.0.0.1");
		connector.setPort(8888);
		connector.setThreadPool(new QueuedThreadPool(20));
		connector.setName("admin");
		server.addConnector(connector);
		// server.addBean(handler);
		// server.addHandler(new JettySSLHandler());
		logger.info("Starting Jetty GSI Server");
		server.start();
	}

	public void setPort(int port) {
		this.port = port;
	}

	public void setProxyLocation(String proxyLocation) {
		this.proxyLocation = proxyLocation;
	}

	public void setCredentialLocation(String credentialLocation) {
		this.credentialLocation = credentialLocation;
	}

	public void setCertificateLocation(String certificateLocation) {
		this.certificateLocation = certificateLocation;
	}

	public void setDefaultTrustCertDirectory(String defaultTrustCertDirectory) {
		this.defaultTrustCertDirectory = defaultTrustCertDirectory;
	}

	public void setTrustStoreDirectories(String trustStoreDirectories) {
		this.trustStoreDirectories = trustStoreDirectories;
	}

	public void setSigningPolicyStoreLocation(String signingPolicyStoreLocation) {
		this.signingPolicyStoreLocation = signingPolicyStoreLocation;
	}

	public void setRejectLimitedProxy(boolean rejectLimitedProxy) {
		this.rejectLimitedProxy = rejectLimitedProxy;
	}

	public void setKeyStoreType(String keyStoreType) {
		this.keyStoreType = keyStoreType;
	}

	public void setKeyStoreLocation(String keyStoreLocation) {
		this.keyStoreLocation = keyStoreLocation;
	}

	public void setKeyStorePassword(String keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}

	public void setTrustStoreType(String trustStoreType) {
		this.trustStoreType = trustStoreType;
	}

	public void setTrustStoreLocation(String trustStoreLocation) {
		this.trustStoreLocation = trustStoreLocation;
	}

	public void setTrustStorePassword(String trustStorePassword) {
		this.trustStorePassword = trustStorePassword;
	}

	public void shutdown() throws Exception {
		this.server.stop();
	}

}
