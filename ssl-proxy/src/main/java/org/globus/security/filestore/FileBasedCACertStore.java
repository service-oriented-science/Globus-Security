package org.globus.security.filestore;

import java.io.File;
import java.io.FilenameFilter;
import java.security.cert.TrustAnchor;

/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Oct 13, 2009 Time: 8:20:32 PM To change this template use File |
 * Settings | File Templates.
 */
public class FileBasedCACertStore extends AbstractFileBasedStore<TrustAnchor> {

    @Override
    protected FileBasedObject<TrustAnchor> create(String fileName) throws FileStoreException {
        return new FileBasedTrustAnchor(new File(fileName));
    }

    @Override
    protected FilenameFilter getFilenameFilter() {
        return FileBasedTrustAnchor.getTrustAnchorFilter();
    }
}
