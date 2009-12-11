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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public abstract class SingleFileBasedObject<T> extends FileBasedObject<T> {

    private static Logger logger =
            LoggerFactory.getLogger(SingleFileBasedObject.class.getName());

    private long lastModified = -1;

    protected File file = null;

    protected void init(File file_) throws FileStoreException {
        validateFilename(file_);
        this.file = file_;
        this.object = createObject(this.file);
        this.lastModified = this.file.lastModified();
    }

    protected void init(File file_, T object_) throws FileStoreException {
        validateFilename(file_);
        if (object_ == null) {
            // FIXME: better exception?
            throw new IllegalArgumentException("Object cannot be null");
        }
        this.object = object_;
        this.file = file_;
    }

    protected void reload() throws FileStoreException {

        this.changed = false;
        long latestLastModified = this.file.lastModified();
        if (this.lastModified < latestLastModified) {
            this.object = createObject(this.file);
            this.lastModified = latestLastModified;
            this.changed = true;
        }
    }

    public File getFile() {
        return this.file;
    }

    // for creation of object from a file

    protected abstract T createObject(File filename)
            throws FileStoreException;

    // for filename validation

    protected abstract void validateFilename(File filename)
            throws FileStoreException;
}
