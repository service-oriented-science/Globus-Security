package org.globus.security.resources;

import org.globus.security.CredentialException;
import org.globus.security.X509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;

/**
 * FIXME: document me
 *
 * @author Tom Howe
 */
public class ResourceProxyCredential extends AbstractResourceSecurityWrapper<X509Credential> {

    Logger logger = LoggerFactory.getLogger(getClass());

    public ResourceProxyCredential(String locationPattern) throws ResourceStoreException {
        init(locationPattern);
    }

    public ResourceProxyCredential(Resource resource) throws ResourceStoreException {
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

        InputStream keyInputStream = null;
        InputStream certInputStream = null;
        try {
            keyInputStream = new BufferedInputStream(resource.getInputStream());
            certInputStream = new BufferedInputStream(resource.getInputStream());
            return new X509Credential(keyInputStream, certInputStream);
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        } catch (CredentialException e) {
            throw new ResourceStoreException(e);
        } finally {

            if (keyInputStream != null) {
                try {
                    keyInputStream.close();
                } catch (Exception e) {
                    logger.warn("Unable to close stream.");
                }
            }
            if (certInputStream != null) {
                try {
                    certInputStream.close();
                } catch (Exception e) {
                    logger.warn("Unable to close stream.");
                }
            }
        }
    }

    public void store() throws ResourceStoreException {
        try {
            X509Credential credential = getCredential();
            credential.writeToFile(resource.getFile());
        } catch (IOException ioe) {
            throw new ResourceStoreException(ioe);
        } catch (CertificateEncodingException e) {
            throw new ResourceStoreException(e);
        }
    }
}
