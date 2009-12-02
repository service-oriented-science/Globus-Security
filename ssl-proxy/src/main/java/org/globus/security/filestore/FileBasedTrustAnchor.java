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
import java.io.FilenameFilter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;

import org.globus.security.util.CertificateLoadUtil;


/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileBasedTrustAnchor extends SingleFileBasedObject<TrustAnchor> {

    private static TrustAnchorFilter filter = new TrustAnchorFilter();

    public FileBasedTrustAnchor(File file) throws FileStoreException {
        init(file);

    }

    public FileBasedTrustAnchor(String fileName, TrustAnchor cachedAnchor) throws FileStoreException {
        init(fileName, cachedAnchor);
    }

    public void refresh() throws FileStoreException {
        super.reload();
    }

    protected TrustAnchor createObject(File file) throws FileStoreException {
        X509Certificate certificate;
        try {
            certificate = CertificateLoadUtil.loadCertificate(
                    new FileInputStream(file));
        } catch (IOException e) {
            throw new FileStoreException(e);
        } catch (GeneralSecurityException e) {
            throw new FileStoreException(e);
        }

        return new TrustAnchor(certificate, null);
    }

    protected void validateFilename(File file) throws FileStoreException {

        if (!filter.accept(file.getParentFile(), file.getName())) {
            // FIXME exceptions
            throw new IllegalArgumentException();
        }
    }

    public TrustAnchor getTrustAnchor() throws FileStoreException {

        TrustAnchor trustAnchor = getObject();
        return trustAnchor;
    }

    public static FilenameFilter getTrustAnchorFilter() {
        return filter;
    }

    public static class TrustAnchorFilter implements FilenameFilter {

        public boolean accept(File dir, String file) {

            if (file == null) {
                throw new IllegalArgumentException();
            }
            int length = file.length();
            return length > 2 &&
                    file.charAt(length - 2) == '.' &&
                    file.charAt(length - 1) >= '0' &&
                    file.charAt(length - 1) <= '9';
        }
    }

}
