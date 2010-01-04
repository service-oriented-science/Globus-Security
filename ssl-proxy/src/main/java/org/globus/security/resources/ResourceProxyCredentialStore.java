package org.globus.security.resources;

import org.globus.security.X509Credential;
import org.globus.security.filestore.FileStoreException;
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
public class ResourceProxyCredentialStore extends ResourceSecurityWrapperStore<ResourceProxyCredential, X509Credential> {
    private Logger logger = LoggerFactory.getLogger(getClass());
    private static FilenameFilter filter = new ProxyFilenameFilter();

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

    public static class ProxyFilenameFilter implements FilenameFilter{
        public boolean accept(File file, String s) {
            return true;
        }
    }
}
