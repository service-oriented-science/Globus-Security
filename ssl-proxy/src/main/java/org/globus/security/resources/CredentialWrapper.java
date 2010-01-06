package org.globus.security.resources;

import org.globus.security.X509Credential;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 5, 2010
 * Time: 4:51:06 PM
 * To change this template use File | Settings | File Templates.
 */
public interface CredentialWrapper extends SecurityObjectWrapper<X509Credential>, Storable{

    public X509Credential getCredential() throws ResourceStoreException;

}
