package org.globus.crux.jsse.internal;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Properties;

import org.globus.crux.jsse.AbstractNamedSecurityObject;
import org.globus.crux.jsse.KeystoreHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CruxKeystore extends AbstractNamedSecurityObject implements
		KeystoreHolder {
	private String proxyCredentialPath;
	private String keyLocation;
	private String certificateLocation;
	private String defaultTrustDirectory;
	private String trustedCertLocations;
	private String name;
	private KeyStore localKeystore;
	private Logger logger = LoggerFactory.getLogger(getClass());

	public KeyStore getKeyStore() {
		logger.info("Starting to create keystore");
		if (localKeystore == null) {
			try {
				ByteArrayInputStream bais = null;
				if (proxyCredentialPath != null) {
					Properties props = new Properties();
					props.put("proxyFilename", proxyCredentialPath);
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					props.store(baos, "");
					bais = new ByteArrayInputStream(baos.toByteArray());
				} else if (certificateLocation != null && keyLocation != null) {
					Properties props = new Properties();
					props.put("certificateFilename", certificateLocation);
					props.put("keyFilename", keyLocation);
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					props.store(baos, "");
					bais = new ByteArrayInputStream(baos.toByteArray());
				} else {
					Properties props = new Properties();
					props.put("directory_list", trustedCertLocations);
					props.put("default_directory", defaultTrustDirectory);
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					props.store(baos, "");
					bais = new ByteArrayInputStream(baos.toByteArray());
				}
				localKeystore = KeyStore.getInstance("PEMFilebasedKeyStore");
				localKeystore.load(bais, null);
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		logger.info("Keystore created");
		return localKeystore;
	}

	public String getProxyCredentialPath() {
		return proxyCredentialPath;
	}

	public void setProxyCredentialPath(String proxyCredentialPath) {
		this.proxyCredentialPath = proxyCredentialPath;
	}

	public String getKeyLocation() {
		return keyLocation;
	}

	public void setKeyLocation(String keyLocation) {
		this.keyLocation = keyLocation;
	}

	public String getCertificateLocation() {
		return certificateLocation;
	}

	public void setCertificateLocation(String certificateLocation) {
		this.certificateLocation = certificateLocation;
	}

	public String getDefaultTrustDirectory() {
		return defaultTrustDirectory;
	}

	public void setDefaultTrustDirectory(String defaultTrustDirectory) {
		this.defaultTrustDirectory = defaultTrustDirectory;
	}

	public String getTrustedCertLocations() {
		return trustedCertLocations;
	}

	public void setTrustedCertLocations(String trustedCertLocations) {
		this.trustedCertLocations = trustedCertLocations;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public KeyStore getLocalKeystore() {
		return localKeystore;
	}

	public void setLocalKeystore(KeyStore localKeystore) {
		this.localKeystore = localKeystore;
	}

}
