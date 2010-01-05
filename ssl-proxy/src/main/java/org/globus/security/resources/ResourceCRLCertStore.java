package org.globus.security.resources;

import org.globus.security.filestore.FileStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.FilenameFilter;
import java.security.cert.X509CRL;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 12:44:12 PM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceCRLCertStore extends ResourceSecurityWrapperStore<ResourceCRL, X509CRL> {
    private Logger logger = LoggerFactory.getLogger(getClass());
    private static CrlFilter filter = new CrlFilter();

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

    public static class CrlFilter implements FilenameFilter {

        public boolean accept(File dir, String file) {

            if (file == null) {
                throw new IllegalArgumentException();
            }

            int length = file.length();
            return length > 3 &&
                    file.charAt(length - 3) == '.' &&
                    file.charAt(length - 2) == 'r' &&
                    file.charAt(length - 1) >= '0' &&
                    file.charAt(length - 1) <= '9';

        }
    }
}
