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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import org.globus.security.CredentialException;
import org.globus.security.X509Credential;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileBasedProxyCredential extends SingleFileBasedObject<X509Credential> {

    Logger logger = LoggerFactory.getLogger(FileBasedProxyCredential.class);

    public FileBasedProxyCredential(File filename)
            throws FileStoreException {

        init(filename);
    }

    public FileBasedProxyCredential(String filename, X509Credential object) throws FileStoreException {
        init(filename, object);
    }

    public X509Credential getCredential() throws FileStoreException {
        X509Credential credential = getObject();
        return credential;
    }

    protected X509Credential createObject(File filename) throws FileStoreException {

        InputStream input = null;
        try {
            input = new FileInputStream(filename);
            return new X509Credential(input);
        } catch (FileNotFoundException e) {
            throw new FileStoreException(e);
        } catch (CredentialException e) {
            throw new FileStoreException(e);
        } finally {

            if (input != null) {
                try {
                    input.close();

                } catch (Exception e) {
                    logger.warn("Unable to close stream.");
                }
            }
        }
    }

    // no restrictions on proxy file name.
    protected void validateFilename(File filename) throws FileStoreException {

    }
}

