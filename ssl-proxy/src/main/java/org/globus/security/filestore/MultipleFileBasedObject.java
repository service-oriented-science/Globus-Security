/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.security.filestore;

import java.io.File;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public abstract class MultipleFileBasedObject<T> extends FileBasedObject<T> {

    private long certLastModified = -1;
    private long keyLastModified = -1;
    private File certFile = null;
    private File keyFile = null;


    protected void init(File certFile_, File keyFile_) throws FileStoreException {
        // FIXME: null checks
        this.certFile = certFile_;
        this.keyFile = keyFile_;
        this.object = createObject(this.certFile, this.keyFile);
        this.certLastModified = this.certFile.lastModified();
        this.keyLastModified = this.keyFile.lastModified();
    }

    protected void init(String certFilename, String keyFilename, T object_) throws FileStoreException {

        if (object_ == null) {
            // FIXME: better exception?
            throw new IllegalArgumentException("Object cannot be null");
        }
        this.object = object_;
        this.certFile = new File(certFilename);
        this.keyFile = new File(keyFilename);
    }


    protected void reload() throws FileStoreException {

        this.changed = false;
        long cLatestLastModified = this.certFile.lastModified();
        long kLatestLastModified = this.keyFile.lastModified();
        if ((this.certLastModified < cLatestLastModified) ||
                (this.keyLastModified < kLatestLastModified)) {
            this.object = createObject(this.certFile, this.keyFile);
            this.certLastModified = cLatestLastModified;
            this.keyLastModified = kLatestLastModified;
            this.changed = true;
        }
    }

    public File getCertificateFile() {
        return this.certFile;
    }

    public File getKeyFile() {
        return this.keyFile;
    }

    // for creation of object from a file
    protected abstract T createObject(File certFilename, File keyFilename)
            throws FileStoreException;


}
