/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.globus.security.stores;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.util.logging.Logger;

import org.globus.security.CredentialException;
import org.globus.security.X509Credential;
import org.springframework.core.io.Resource;

/**
 * FIXME: document me
 *
 * @author Tom Howe
 */
public class ResourceProxyCredential extends AbstractResourceSecurityWrapper<X509Credential>
        implements CredentialWrapper {

    private Logger logger = Logger.getLogger(getClass().getCanonicalName());

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
                    logger.warning("Unable to close stream.");
                }
            }
            if (certInputStream != null) {
                try {
                    certInputStream.close();
                } catch (Exception e) {
                    logger.warning("Unable to close stream.");
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
