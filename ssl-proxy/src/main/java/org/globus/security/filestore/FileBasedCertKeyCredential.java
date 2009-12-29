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

import org.globus.security.CredentialException;
import org.globus.security.X509Credential;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileBasedCertKeyCredential extends MultipleFileBasedObject<X509Credential> implements FileBasedCredential {


    public FileBasedCertKeyCredential(File certFile, File keyFile) throws FileStoreException {

        init(certFile, keyFile);
    }

    public FileBasedCertKeyCredential(File certFile, File keyFile,
                                      X509Credential credential) throws FileStoreException {

        init(certFile, keyFile, credential);
    }

    @Override
    protected X509Credential createObject(File certFilename, File keyFilename) throws FileStoreException {
        FileInputStream certIns;
        FileInputStream keyIns;
        try {
            certIns = new FileInputStream(certFilename);
            keyIns = new FileInputStream(keyFilename);
            X509Credential credential = new X509Credential(certIns, keyIns);
            return credential;
        } catch (FileNotFoundException e) {
            throw new FileStoreException(e);
        } catch (CredentialException e) {
            throw new FileStoreException(e);
        }
    }
<<<<<<< HEAD

    public X509Credential getCredential() throws FileStoreException {
        X509Credential credential = getObject();
        return credential;
    }
<<<<<<< HEAD

    public void storeCredential() throws FileStoreException {

        try {
            this.object.writeToFile(this.certFile, this.keyFile);
        } catch (IOException e) {
            throw new FileStoreException(e);
        } catch (CertificateEncodingException e) {
            throw new FileStoreException(e);
        }
    }
=======
>>>>>>> a64ce28... filebasedobject rework take1
=======
>>>>>>> 9675559... Write to file improved. Tests work now.
}
