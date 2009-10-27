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
package org.globus.security;

import java.security.cert.CertPathValidatorResult;
import java.security.cert.X509Certificate;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class X509ProxyCertPathValidatorResult
        implements CertPathValidatorResult {

    X509Certificate idenX509Certificate;
    boolean limited = false;

    public X509ProxyCertPathValidatorResult(
            X509Certificate identityCertificate_) {
        this(identityCertificate_, false);
    }

    public X509ProxyCertPathValidatorResult(
            X509Certificate identityCertificate_, boolean limited_) {
        if (identityCertificate_ != null) {
            this.idenX509Certificate = identityCertificate_;
        }
        this.limited = limited_;
    }

    public X509Certificate getIdentityCertificate() {
        return this.idenX509Certificate;
    }

    public boolean isLimited() {
        return this.limited;
    }

    /**
     * Makes a copy of this <code>CertPathValidatorResult</code>. Changes to the
     * copy will not affect the original and vice versa.
     *
     * @return a copy of this <code>CertPathValidatorResult</code>
     */
    public Object clone() {
        //TODO: at a minimum this requires call to super
        try {
            super.clone();
        } catch (CloneNotSupportedException e) {
            e.printStackTrace();  //CHANGEME To change body of catch statement use File | Settings | File Templates.
        }
        return null;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }
}
