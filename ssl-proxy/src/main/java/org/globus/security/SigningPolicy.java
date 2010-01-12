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


import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.globus.security.util.CertificateUtil;
import org.globus.security.util.SigningPolicyFileParser;

/**
 * Represents a signing policy associated with a particular CA.
 *
 * @author ranantha@mcs.anl.gov
 */
public class SigningPolicy {

    private X500Principal caSubject;
    private Vector<Pattern> allowedDNs;

    public SigningPolicy(X500Principal caSubjectDN, String[] allowedDNs) {

        if ((caSubjectDN == null) || (allowedDNs == null)) {
            throw new IllegalArgumentException();
        }

        this.caSubject = caSubjectDN;
        int numberOfDNs = allowedDNs.length;
        this.allowedDNs = new Vector<Pattern>(numberOfDNs);
        for (String anAllowedDNs : allowedDNs) {
            this.allowedDNs.add(SigningPolicyFileParser.
                getPattern(anAllowedDNs));

        }
    }

    public SigningPolicy(
        X500Principal caSubjectDN,
        Vector<Pattern> allowedDNs) {

        if ((caSubjectDN == null) || (allowedDNs == null)) {
            throw new IllegalArgumentException();
        }

        this.caSubject = caSubjectDN;
        this.allowedDNs = allowedDNs;
    }

    /**
     * Get CA subject DN for which this signing policy is defined
     *
     * @return returns the CA subject
     */
    public X500Principal getCASubjectDN() {
        return this.caSubject;
    }

    /**
     * Ascertains if the subjectDN is valid against this policy.
     *
     * @param subject Subject DN to be validated
     * @return true if the DN is valid under this policy and false if it is not
     */
    public boolean isValidSubject(X500Principal subject) {

        if (subject == null) {
            throw new IllegalArgumentException();
        }

        String subjectDN = CertificateUtil.toGlobusID(subject);

        // no policy
        // FIXME: probably should be false?
        if ((this.allowedDNs == null) || (this.allowedDNs.size() < 1)) {
            return true;
        }

        int size = this.allowedDNs.size();
        for (int i = 0; i < size; i++) {
            Pattern pattern = allowedDNs.get(i);
            Matcher matcher = pattern.matcher(subjectDN);
            boolean valid = matcher.matches();
            if (valid) {
                return true;
            }
        }

        return false;
    }

    public Vector<Pattern> getAllowedDNs() {
        return this.allowedDNs;
    }
}
