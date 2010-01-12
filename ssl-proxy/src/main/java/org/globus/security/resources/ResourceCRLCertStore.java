package org.globus.security.resources;

import java.io.File;
import java.io.FilenameFilter;
import java.security.cert.X509CRL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

/**
 * Fill Me
 */
public class ResourceCRLCertStore extends ResourceSecurityWrapperStore<ResourceCRL, X509CRL> {
    private static CrlFilter filter = new CrlFilter();

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public ResourceCRL create(Resource resource) throws ResourceStoreException {
        return new ResourceCRL(resource);
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
     * This filter identifies file whose names are valid for crl files.
     */
    public static class CrlFilter implements FilenameFilter {

        public boolean accept(File dir, String file) {

            if (file == null) {
                throw new IllegalArgumentException();
            }

            int length = file.length();
            return length > 3
                && file.charAt(length - 3) == '.'
                && file.charAt(length - 2) == 'r'
                && file.charAt(length - 1) >= '0'
                && file.charAt(length - 1) <= '9';

        }
    }
}
