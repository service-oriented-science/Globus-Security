package org.globus.security.resources;

import java.io.File;
import java.io.FilenameFilter;

import org.globus.security.X509Credential;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

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
