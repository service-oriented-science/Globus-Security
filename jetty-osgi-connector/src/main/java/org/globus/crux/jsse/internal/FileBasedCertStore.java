package org.globus.crux.jsse.internal;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertStore;

import org.globus.crux.jsse.AbstractNamedSecurityObject;
import org.globus.crux.jsse.CRLStoreHolder;
import org.globus.security.stores.ResourceCertStoreParameters;

public class FileBasedCertStore extends AbstractNamedSecurityObject implements CRLStoreHolder {

	private String crlLocations;
	private CertStore instance;
	private String name;

	public CertStore getCertStore() {
		if (instance == null) {
			try {
				instance = CertStore.getInstance("PEMFilebasedCertStore", new ResourceCertStoreParameters(null,
						crlLocations));
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return instance;
	}

	public String getCrlLocations() {
		return crlLocations;
	}

	public void setCrlLocations(String crlLocations) {
		this.crlLocations = crlLocations;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}
