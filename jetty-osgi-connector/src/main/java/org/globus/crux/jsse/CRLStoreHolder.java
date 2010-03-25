package org.globus.crux.jsse;

import java.security.cert.CertStore;

public interface CRLStoreHolder extends NamedSecurityObject{
	public CertStore getCertStore();
}
