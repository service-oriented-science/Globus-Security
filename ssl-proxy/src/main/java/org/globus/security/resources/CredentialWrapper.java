package org.globus.security.resources;

import org.globus.security.X509Credential;

/**
 * Fill Me
 */
public interface CredentialWrapper extends SecurityObjectWrapper<X509Credential>, Storable {

    X509Credential getCredential() throws ResourceStoreException;

}
