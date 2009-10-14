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

import org.globus.security.util.CertificateLoadUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertStoreException;
import java.security.cert.X509CRL;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileBasedCRL extends FileBasedObject<X509CRL> {

    private static CrlFilter filter = new CrlFilter();

    public FileBasedCRL(File file) throws CertStoreException {

        init(file);
    }

    protected X509CRL createObject(File file) throws CertStoreException {

        X509CRL crl;
        try {
            crl = CertificateLoadUtil.loadCrl(new FileInputStream(file));
        } catch (IOException e) {
            throw new CertStoreException(e);
        } catch (GeneralSecurityException e) {
            throw new CertStoreException(e);
        }

        return crl;
    }

    protected void validateFilename(File file) throws CertStoreException {

        if (!filter.accept(null, file.getAbsolutePath())) {
            // FIXME exceptions
            throw new IllegalArgumentException();
        }
    }

    public X509CRL getCrl() throws CertStoreException {

        return getObject();
    }

    public static FilenameFilter getCrlFilter() {
        return filter;
    }

    public static class CrlFilter implements FilenameFilter {

        public boolean accept(File dir, String file) {

            if (file == null) {
                throw new IllegalArgumentException();
            }

            int length = file.length();
            return length > 3 &&
                    file.charAt(length - 3) == '.' &&
                    file.charAt(length - 2) == 'r' &&
                    file.charAt(length - 1) >= '0' &&
                    file.charAt(length - 1) <= '9';

        }
    }


}
