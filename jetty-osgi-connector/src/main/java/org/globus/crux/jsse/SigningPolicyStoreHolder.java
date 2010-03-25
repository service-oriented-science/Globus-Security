package org.globus.crux.jsse;

import org.globus.security.SigningPolicyStore;

public interface SigningPolicyStoreHolder extends NamedSecurityObject {
	public SigningPolicyStore getSigningPolicyStore();
}
