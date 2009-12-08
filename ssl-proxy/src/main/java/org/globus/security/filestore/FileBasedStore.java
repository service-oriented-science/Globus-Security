package org.globus.security.filestore;

import java.util.Collection;
import java.util.Map;

/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Oct 13, 2009 Time: 4:09:25 PM To change this template use File |
 * Settings | File Templates. TODO: This should probably just be a generic class with <T,V> representing TODO: wrapper
 * and the core type.
 */
public abstract class FileBasedStore<T> {

    public static enum LoadFileType {

        CA_FILE, CRL_FILE,
    }

    public static FileBasedStore getFileBasedStore(LoadFileType fileType) {
        switch (fileType) {
            case CA_FILE:
                return new FileBasedCACertStore();
            case CRL_FILE:
                return new FileBasedCRLStore();
            default:
                return null;
        }
    }

    public abstract void loadWrappers(String[] locations)
            throws FileStoreException;


    public abstract Map<String, FileBasedObject<T>> getWrapperMap();

    public abstract Collection<T> getCollection();
}
