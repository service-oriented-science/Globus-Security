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

import org.globus.security.X509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.FilenameFilter;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 12:53:02 PM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceProxyCredentialStore
        extends ResourceSecurityWrapperStore<ResourceProxyCredential, X509Credential> {

    private static FilenameFilter filter = new ProxyFilenameFilter();

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public ResourceProxyCredential create(Resource resource) throws ResourceStoreException {
        return new ResourceProxyCredential(resource);
    }

    @Override
    protected Logger getLogger() {
        return logger;
    }

    @Override
    public FilenameFilter getDefaultFilenameFilter() {
        return ResourceProxyCredentialStore.filter;
    }

    /**
     * This filename filter returns files whose names are valid for a Proxy Certificate.
     */
    public static class ProxyFilenameFilter implements FilenameFilter {
        public boolean accept(File file, String s) {
            return true;
        }
    }
}
