package org.globus.security.resources;

import org.globus.security.CredentialException;
import org.globus.security.X509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 12:47:17 PM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceProxyCredential extends ResourceSecurityWrapper<X509Credential> {

    Logger logger = LoggerFactory.getLogger(getClass());

    public ResourceProxyCredential(String locationPattern) throws ResourceStoreException {
        init(locationPattern);
    }

    public ResourceProxyCredential(Resource resource) throws ResourceStoreException{
        init(resource);
    }

    public ResourceProxyCredential(String filename, X509Credential object) throws ResourceStoreException {
        init(filename, object);
    }

    public ResourceProxyCredential(Resource resource, X509Credential object) throws ResourceStoreException {
        init(resource, object);
    }

    public X509Credential getCredential() throws ResourceStoreException {
        return getSecurityObject();
    }

    protected X509Credential create(Resource resource) throws ResourceStoreException {

        InputStream input = null;
        try {
            input = new BufferedInputStream(resource.getInputStream());
            return new X509Credential(input);
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        } catch (CredentialException e) {
            throw new ResourceStoreException(e);
        } finally {

            if (input != null) {
                try {
                    input.close();

                } catch (Exception e) {
                    logger.warn("Unable to close stream.");
                }
            }
        }
    }
}
