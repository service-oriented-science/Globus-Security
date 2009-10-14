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

import org.globus.security.util.CertificateIOUtil;
import org.globus.security.util.CertificateLoadUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertStoreException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;


/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileBasedTrustAnchor extends FileBasedObject<TrustAnchor> 
        implements TrustAnchorWrapper {

    private static TrustAnchorFilter filter = new TrustAnchorFilter();
    private String alias;
    private TrustAnchor memoryAnchor;

    public FileBasedTrustAnchor(File file) throws CertStoreException {
        init(file);
    }

    public FileBasedTrustAnchor(String alias, TrustAnchor cachedAnchor){
        this.alias = alias;
        this.memoryAnchor = cachedAnchor;
    }
    
    public String getAlias() {
        return alias;
    }

    public void refresh() throws CertStoreException {
        super.reload();
    }

    protected TrustAnchor createObject(File file) throws CertStoreException {
        X509Certificate certificate;
        if(memoryAnchor != null){
            return memoryAnchor;
        }
        try {
            certificate = CertificateLoadUtil.loadCertificate(
                    new FileInputStream(file));
        } catch (IOException e) {
            throw new CertStoreException(e);
        } catch (GeneralSecurityException e) {
            throw new CertStoreException(e);
        }

        return new TrustAnchor(certificate, null);
    }

    protected void validateFilename(File file) throws CertStoreException {

        if (!filter.accept(file.getParentFile(), file.getName())) {
            // FIXME exceptions
            throw new IllegalArgumentException();
        }
    }

    public TrustAnchor getTrustAnchor() throws CertStoreException {
        TrustAnchor trustAnchor = getObject();
        this.alias = CertificateIOUtil.nameHash(
                trustAnchor.getTrustedCert().getSubjectDN());
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

