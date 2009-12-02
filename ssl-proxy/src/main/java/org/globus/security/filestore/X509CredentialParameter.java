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

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class X509CredentialParameter {

    String certKeyFilename;
    String certificateFilename;
    String keyFilename;

    public X509CredentialParameter(String certKeyFilename_) {

        if (certKeyFilename_ == null) {
            throw new IllegalArgumentException();
        }

        this.certKeyFilename = certKeyFilename_;
    }

    public X509CredentialParameter(String certificateFilename_, String keyFilename_) {

        if ((certificateFilename_ == null) || (keyFilename_ == null)) {
            throw new IllegalArgumentException();
        }

        this.certificateFilename = certificateFilename_;
        this.keyFilename = keyFilename_;
    }

    public String getCertKeyFilename() {
        return this.certKeyFilename;
    }

    public String getCertificateFilename() {
        return this.certificateFilename;
    }

    public String getKeyFilename() {
        return this.keyFilename;
    }
}
