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
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;

import org.globus.security.CredentialException;
import org.globus.security.X509Credential;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileBasedProxyCredential extends SingleFileBasedObject<X509Credential> implements FileBasedCredential {

    Logger logger = LoggerFactory.getLogger(FileBasedProxyCredential.class);

    public FileBasedProxyCredential(File file) throws FileStoreException {

        init(file);
    }

    public FileBasedProxyCredential(File file, X509Credential object) throws FileStoreException {
        init(file, object);
    }

    public X509Credential getCredential() throws FileStoreException {
        X509Credential credential = getObject();
        return credential;
    }

    protected X509Credential createObject(File file) throws FileStoreException {

        InputStream keyInput = null;
        InputStream certInput = null;
        try {
            keyInput = new FileInputStream(file);
            certInput = new FileInputStream(file);
            return new X509Credential(certInput, keyInput);
        } catch (FileNotFoundException e) {
            throw new FileStoreException(e);
        } catch (CredentialException e) {
            throw new FileStoreException(e);
        } finally {

            if (keyInput != null) {
                try {
                    keyInput.close();
                } catch (Exception e) {
                    logger.warn("Unable to close stream.");
                }
            }

            if (certInput != null) {
                try {
                    certInput.close();
                } catch (Exception e) {
                    logger.warn("Unable to close stream.");
                }
            }

        }
    }

    public void storeCredential() throws FileStoreException {

        try {
            this.object.writeToFile(this.file);
        } catch (IOException e) {
            throw new FileStoreException(e);
        } catch (CertificateEncodingException e) {
            throw new FileStoreException(e);
        }
    }

    // no restrictions on proxy file name.

    protected void validateFilename(File file) throws FileStoreException {

    }
}

