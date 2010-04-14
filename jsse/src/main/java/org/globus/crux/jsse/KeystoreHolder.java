package org.globus.crux.jsse;

import java.security.KeyStore;

public interface KeystoreHolder extends NamedSecurityObject {

	public KeyStore getKeyStore();

}
