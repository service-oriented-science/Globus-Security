package org.globus.crux.jsse.internal;

import java.security.InvalidAlgorithmParameterException;

import org.globus.crux.jsse.AbstractNamedSecurityObject;
import org.globus.crux.jsse.SigningPolicyStoreHolder;
import org.globus.security.SigningPolicyStore;
import org.globus.security.stores.ResourceSigningPolicyStore;
import org.globus.security.stores.ResourceSigningPolicyStoreParameters;

public class CruxSigningPolicyStore extends AbstractNamedSecurityObject implements SigningPolicyStoreHolder {
	private String name;
	private String signingPolicyLocations;
	private SigningPolicyStore instance;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public SigningPolicyStore getSigningPolicyStore() {
		if (instance == null) {
			ResourceSigningPolicyStoreParameters params = new ResourceSigningPolicyStoreParameters(
					signingPolicyLocations);
			try {
				instance = new ResourceSigningPolicyStore(params);
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return instance;
	}

	public String getSigningPolicyLocations() {
		return signingPolicyLocations;
	}

	public void setSigningPolicyLocations(String signingPolicyLocations) {
		this.signingPolicyLocations = signingPolicyLocations;
	}

}
