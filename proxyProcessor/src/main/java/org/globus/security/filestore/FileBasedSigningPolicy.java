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

import org.globus.security.SigningPolicy;
import org.globus.security.SigningPolicyException;
import org.globus.security.SigningPolicyStoreException;
import org.globus.security.util.SigningPolicyFileParser;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.util.Collection;
import java.util.Map;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileBasedSigningPolicy extends FileBasedObject<Map<X500Principal, SigningPolicy>> {


    public final static String SIGNING_POLICY_FILE_SUFFIX = ".signing_policy";

    private static SigningPolicyFilter filter = new SigningPolicyFilter();

    public FileBasedSigningPolicy(File filename)
        throws FileStoreException {
        init(filename);

    }

    protected Map<X500Principal, SigningPolicy> createObject(File filename)
        throws FileStoreException {

        SigningPolicyFileParser parser = new SigningPolicyFileParser();
        Map<X500Principal, SigningPolicy> policies;
        try {
            policies = parser.parse(new FileReader(filename));
        } catch (FileNotFoundException e) {
            throw new FileStoreException(e);
        } catch (SigningPolicyException e) {
            throw new FileStoreException(e);
        }

        return policies;

    }

    protected void validateFilename(File file) throws FileStoreException {
        if (!(filter.accept(file.getParentFile(), file.getName()))) {
            throw new IllegalArgumentException();
        }
    }

    public Collection<SigningPolicy> getSigningPolicies()
        throws SigningPolicyStoreException {

        try {
            Map<X500Principal, SigningPolicy> object = getObject();
            if (object != null) {
                return object.values();
            }
        } catch (FileStoreException e) {
            throw new SigningPolicyStoreException(e);
        }
        return null;
    }

    public SigningPolicy getSigningPolicy(X500Principal caDN)
        throws SigningPolicyStoreException {

        try {
            Map<X500Principal, SigningPolicy> object = getObject();
            if (object != null) {
                Map<X500Principal, SigningPolicy> map =
                    (object);
                return map.get(caDN);
            }
        } catch (FileStoreException e) {
            throw new SigningPolicyStoreException(e);
        }
        return null;
    }

    public static FilenameFilter getSigningPolicyFilter() {
        return filter;
    }

    public static class SigningPolicyFilter implements FilenameFilter {

        public boolean accept(File dir, String file) {
            if (file == null) {
                throw new IllegalArgumentException();
            }
            return file.endsWith(SIGNING_POLICY_FILE_SUFFIX);
        }
    }
}