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

import java.security.cert.CertStoreParameters;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileCertStoreParameters implements CertStoreParameters {


    // FIXME: make this configurable.
    public static String[] DEFAULT_DIRECTORIES =
            new String[]{"/etc/grid-security/certificaes",
                    "~/.globus/certificates"};

    String[] trustrootDirectories;

    public FileCertStoreParameters(String[] trustrootDir_) {

        if (trustrootDir_ == null) {
            this.trustrootDirectories = DEFAULT_DIRECTORIES;
        } else {
            this.trustrootDirectories = trustrootDir_;
        }
    }

    public String[] getTrustRootLocations() {

        return this.trustrootDirectories;
    }

    /**
     * Makes a copy of this <code>CertStoreParameters</code>.
     * <p/>
     * The precise meaning of "copy" may depend on the class of the
     * <code>CertStoreParameters</code> object. A typical implementation
     * performs a "deep copy" of this object, but this is not an absolute
     * requirement. Some implementations may perform a "shallow copy" of some or
     * all of the fields of this object.
     * <p/>
     * Note that the <code>CertStore.getInstance</code> methods make a copy of
     * the specified <code>CertStoreParameters</code>. A deep copy
     * implementation of <code>clone</code> is safer and more robust, as it
     * prevents the caller from corrupting a shared <code>CertStore</code> by
     * subsequently modifying the contents of its initialization parameters.
     * However, a shallow copy implementation of <code>clone</code> is more
     * appropriate for applications that need to hold a reference to a parameter
     * contained in the <code>CertStoreParameters</code>. For example, a shallow
     * copy clone allows an application to release the resources of a particular
     * <code>CertStore</code> initialization parameter immediately, rather than
     * waiting for the garbage collection mechanism. This should be done with
     * the utmost care, since the <code>CertStore</code> may still be in use by
     * other threads.
     * <p/>
     * Each subclass should state the precise behavior of this method so that
     * users and developers know what to expect.
     *
     * @return a copy of this <code>CertStoreParameters</code>
     */
    public Object clone() {
        return null;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }
}
