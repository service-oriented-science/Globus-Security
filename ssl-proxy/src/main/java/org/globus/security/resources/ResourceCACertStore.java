package org.globus.security.resources;

import java.io.File;
import java.io.FilenameFilter;
import java.security.cert.TrustAnchor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 11:49:20 AM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceCACertStore extends ResourceSecurityWrapperStore<ResourceTrustAnchor, TrustAnchor> {
    private static FilenameFilter filter = new TrustAnchorFilter();

    private Logger logger = LoggerFactory.getLogger(getClass());

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

    /**
     * File filter for determining a Trust Anchor
     */
    public static class TrustAnchorFilter implements FilenameFilter {

        public boolean accept(File dir, String file) {

            if (file == null) {
                throw new IllegalArgumentException();
            }
            int length = file.length();
            return length > 2
                && file.charAt(length - 2) == '.'
                && file.charAt(length - 1) >= '0'
                && file.charAt(length - 1) <= '9';
        }
    }
}
