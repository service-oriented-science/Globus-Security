package org.globus.security.filestore;

import java.io.File;
import java.security.cert.CertStoreException;
import java.security.cert.TrustAnchor;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Oct 13, 2009
 * Time: 2:50:13 PM
 * To change this template use File | Settings | File Templates.
 */
public interface TrustAnchorWrapper {
    TrustAnchor getTrustAnchor() throws CertStoreException;

    File getFile();

    void setFile(File file);

    String getAlias();
            
    boolean hasChanged();
}
