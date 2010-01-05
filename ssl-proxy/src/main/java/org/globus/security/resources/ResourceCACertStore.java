package org.globus.security.resources;

import org.globus.security.filestore.FileStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.FilenameFilter;
import java.security.cert.TrustAnchor;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 11:49:20 AM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceCACertStore extends ResourceSecurityWrapperStore<ResourceTrustAnchor, TrustAnchor> {
    private Logger logger = LoggerFactory.getLogger(getClass());
    private static FilenameFilter filter = new TrustAnchorFilter();

    @Override
    public ResourceTrustAnchor create(Resource resource) throws ResourceStoreException {
        return new ResourceTrustAnchor(resource);
    }

    @Override
    protected Logger getLogger() {
        return logger;
    }

    @Override
    public FilenameFilter getDefaultFilenameFilter() {
        return filter;
    }

    public static class TrustAnchorFilter implements FilenameFilter {

        public boolean accept(File dir, String file) {

            if (file == null) {
                throw new IllegalArgumentException();
            }
            int length = file.length();
            return length > 2 &&
                    file.charAt(length - 2) == '.' &&
                    file.charAt(length - 1) >= '0' &&
                    file.charAt(length - 1) <= '9';
        }
    }
}
