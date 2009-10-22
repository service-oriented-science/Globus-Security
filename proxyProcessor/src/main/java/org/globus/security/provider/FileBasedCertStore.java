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
package org.globus.security.provider;

import org.globus.security.filestore.FileBasedStore;
import org.globus.security.filestore.FileCertStoreParameters;
import org.globus.security.filestore.FileStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Vector;


/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileBasedCertStore extends CertStoreSpi {

    private static Logger logger =
        LoggerFactory.getLogger(FileBasedCertStore.class.getName());


    private FileBasedStore caDelegate =
        FileBasedStore.getFileBasedStore(FileBasedStore.LoadFileType.CA_FILE);

    private FileBasedStore crlDelegate =
        FileBasedStore.getFileBasedStore(FileBasedStore.LoadFileType.CRL_FILE);

    private FileCertStoreParameters storeParams = null;

    /**
     * The sole constructor.
     *
     * @param params the initialization parameters (may be <code>null</code>)
     * @throws java.security.InvalidAlgorithmParameterException
     *          if the initialization parameters are inappropriate for this <code>CertStoreSpi</code>
     */
    public FileBasedCertStore(CertStoreParameters params)
        throws InvalidAlgorithmParameterException {
        super(params);
        if (params == null) {
            throw new InvalidAlgorithmParameterException();
        }

        if (params instanceof FileCertStoreParameters) {
            this.storeParams = (FileCertStoreParameters)params;
        } else {
            throw new InvalidAlgorithmParameterException();
        }
    }

    /**
     * Returns a <code>Collection</code> of <code>Certificate</code>s that match the specified selector. If no
     * <code>Certificate</code>s match the selector, an empty <code>Collection</code> will be returned.
     * <p/>
     * For some <code>CertStore</code> types, the resulting <code>Collection</code> may not contain <b>all</b> of the
     * <code>Certificate</code>s that match the selector. For instance, an LDAP <code>CertStore</code> may not search
     * all entries in the directory. Instead, it may just search entries that are likely to contain the
     * <code>Certificate</code>s it is looking for.
     * <p/>
     * Some <code>CertStore</code> implementations (especially LDAP <code>CertStore</code>s) may throw a
     * <code>CertStoreException</code> unless a non-null <code>CertSelector</code> is provided that includes specific
     * criteria that can be used to find the certificates. Issuer and/or subject names are especially useful criteria.
     *
     * @param selector A <code>CertSelector</code> used to select which <code>Certificate</code>s should be returned.
     *                 Specify <code>null</code> to return all <code>Certificate</code>s (if supported).
     * @return A <code>Collection</code> of <code>Certificate</code>s that match the specified selector (never
     *         <code>null</code>)
     * @throws java.security.cert.CertStoreException
     *          if an exception occurs
     */
    public Collection<? extends Certificate>
    engineGetCertificates(CertSelector selector) throws CertStoreException {
        logger.debug("selecting Certificates");
        if (selector != null) {
            if (!(selector instanceof X509CertSelector)) {
                throw new IllegalArgumentException();
            }
        }

        try {
            caDelegate.loadWrappers(this.storeParams.getTrustRootLocations());
        } catch (FileStoreException e) {
            throw new CertStoreException(e);
        }

        if (caDelegate.getCollection() == null) {
            return null;
        }
        // Given that we always only use subject, how can we improve performance
        // here. Custom
        Vector<X509Certificate> certSet = new Vector<X509Certificate>();
        if (selector == null) {
            for (TrustAnchor trustAnchor : (Collection<TrustAnchor>)caDelegate
                .getCollection()) {
                certSet.add(trustAnchor.getTrustedCert());
            }

        } else {
            for (TrustAnchor trustAnchor : (Collection<TrustAnchor>)caDelegate
                .getCollection()) {
                X509Certificate cert = trustAnchor.getTrustedCert();
                if (selector.match(cert)) {
                    certSet.add(cert);
                }
            }
        }

        return certSet;
    }

    /**
     * Returns a <code>Collection</code> of <code>CRL</code>s that match the specified selector. If no <code>CRL</code>s
     * match the selector, an empty <code>Collection</code> will be returned.
     * <p/>
     * For some <code>CertStore</code> types, the resulting <code>Collection</code> may not contain <b>all</b> of the
     * <code>CRL</code>s that match the selector. For instance, an LDAP <code>CertStore</code> may not search all
     * entries in the directory. Instead, it may just search entries that are likely to contain the <code>CRL</code>s it
     * is looking for.
     * <p/>
     * Some <code>CertStore</code> implementations (especially LDAP <code>CertStore</code>s) may throw a
     * <code>CertStoreException</code> unless a non-null <code>CRLSelector</code> is provided that includes specific
     * criteria that can be used to find the CRLs. Issuer names and/or the certificate to be checked are especially
     * useful.
     *
     * @param selector A <code>CRLSelector</code> used to select which <code>CRL</code>s should be returned. Specify
     *                 <code>null</code> to return all <code>CRL</code>s (if supported).
     * @return A <code>Collection</code> of <code>CRL</code>s that match the specified selector (never
     *         <code>null</code>)
     * @throws java.security.cert.CertStoreException
     *          if an exception occurs
     */
    public Collection<? extends CRL> engineGetCRLs(CRLSelector selector)
        throws CertStoreException {

        if (selector != null) {
            if (!(selector instanceof X509CRLSelector)) {
                throw new IllegalArgumentException();
            }
        }

        try {
            crlDelegate.loadWrappers(this.storeParams.getTrustRootLocations());
        } catch (FileStoreException e) {
            throw new CertStoreException(e);
        }

        if (crlDelegate.getCollection() == null) {
            return new Vector<X509CRL>();
        }

        // Given that we always only use subject, how can we improve performance
        // here. Custom

        if (selector == null) {
            return crlDelegate.getCollection();
        } else {
            Vector<X509CRL> certSet = new Vector<X509CRL>();
            for (X509CRL crl : (Collection<X509CRL>)crlDelegate
                .getCollection()) {
                if (selector.match(crl)) {
                    certSet.add(crl);
                }
            }
            return certSet;
        }
    }
}

