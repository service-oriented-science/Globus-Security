package org.globus.security.filestore;

import java.io.File;
import java.io.FilenameFilter;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Delegator class for handling FileBasedStore implementations
 */
public abstract class AbstractFileBasedStore<T> extends FileBasedStore<T> {

    private Logger logger = LoggerFactory.getLogger(getClass());

    private Map<String, FileBasedObject<T>> wrapperMap = new HashMap<String, FileBasedObject<T>>();

    // Local cache
    private Collection<T> rootObjects;

    @Override
    public Map<String, FileBasedObject<T>> getWrapperMap() {
        return this.wrapperMap;
    }

    @Override
    public void loadWrappers(String[] locations)
            throws FileStoreException {

        if (locations == null) {
            return;
        }

        boolean changed = false;

        File file;

        Map<String, FileBasedObject<T>> newWrapperMap = new HashMap<String, FileBasedObject<T>>();
        Set<T> updatedList = new HashSet<T>();

        for (String location : locations) {

            file = new File(location.trim());

            if (!file.canRead()) {
                logger.debug("Cannot read: " + file.getAbsolutePath());
                continue;
            }

            if (file.isDirectory()) {
                String[] caCertFiles = file.list(getFilenameFilter());
                if (caCertFiles == null) {
                    logger.debug("Cannot load certificates from " +
                            file.getAbsolutePath() + " directory.");
                } else {
                    logger.debug("Loading certificates from " +
                            file.getAbsolutePath() + " directory.");
                    for (String caCertFile : caCertFiles) {
                        String caFilename = file.getPath() +
                                File.separatorChar +
                                caCertFile;

                        FileBasedObject<T> loaded = load(caFilename, updatedList);
                        newWrapperMap.put(caFilename, loaded);
                        updatedList.add(loaded.getObject());
                        changed = true;
                    }
                }
            } else {
                String filename = file.getAbsolutePath();
                if (getFilenameFilter().accept(null, filename)) {
                    FileBasedObject<T> loaded = load(filename, updatedList);
                    newWrapperMap.put(filename, loaded);
                    updatedList.add(loaded.getObject());
                    changed = true;
                }
            }
            // in case certificates were removed
            if (!changed) {
                if (this.rootObjects != null &&
                        this.wrapperMap.size() != newWrapperMap.size()) {
                    changed = true;
                }
            }
            if (changed) {
                this.rootObjects = updatedList;
            }
            this.wrapperMap = newWrapperMap;
        }
    }

    private FileBasedObject<T> load(String fileName, Set<T> currentRoots) throws FileStoreException {
        File caFile = new File(fileName);


        if (!caFile.canRead()) {
            throw new FileStoreException("Cannot read file");
        }

        FileBasedObject<T> fbo = this.wrapperMap.get(fileName);
        if (fbo == null) {
            fbo = create(fileName);
        }
        T target = fbo.getObject();
        this.wrapperMap.put(fileName, fbo);
        currentRoots.add(target);
        return fbo;
    }

    @Override
    public Collection<T> getCollection() {
        return this.rootObjects;
    }

    protected abstract FileBasedObject<T> create(String fileName) throws FileStoreException;

    protected abstract FilenameFilter getFilenameFilter();

}
