package org.globus.security.filestore;

import java.io.File;
import java.io.FilenameFilter;
import java.security.cert.X509CRL;

/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Oct 13, 2009 Time: 8:34:13 PM To change this template use File |
 * Settings | File Templates.
 */
public class FileBasedCRLStore extends AbstractFileBasedStore<X509CRL> {

    @Override
    protected FileBasedObject<X509CRL> create(String fileName) throws FileStoreException {
        return new FileBasedCRL(new File(fileName));
    }

    @Override
    protected FilenameFilter getFilenameFilter() {
        return FileBasedCRL.getCrlFilter();
    }
}
