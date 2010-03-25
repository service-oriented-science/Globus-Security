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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;

import org.globus.security.util.CertificateLoadUtil;
import org.springframework.core.io.Resource;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 12:41:39 PM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceCRL extends AbstractResourceSecurityWrapper<X509CRL> {

    public ResourceCRL(String fileName) throws ResourceStoreException {
        init(resolver.getResource(fileName));
    }

    public ResourceCRL(Resource resource) throws ResourceStoreException {
        init(resource);
    }

    public ResourceCRL(String fileName, X509CRL crl) throws ResourceStoreException {
        init(resolver.getResource(fileName), crl);
    }

    public X509CRL getCrl() throws ResourceStoreException {
        return getSecurityObject();
    }

    @Override
    protected X509CRL create(Resource resource) throws ResourceStoreException {
        try {
            return CertificateLoadUtil.loadCrl(resource.getInputStream());
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        } catch (GeneralSecurityException e) {
            throw new ResourceStoreException(e);
        }
    }

    public void store() throws ResourceStoreException {
        //TODO: does this need an implementation
    }
}