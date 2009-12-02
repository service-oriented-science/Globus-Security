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
import java.io.FilenameFilter;
import java.security.InvalidAlgorithmParameterException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.globus.security.SigningPolicy;
import org.globus.security.SigningPolicyStore;
import org.globus.security.SigningPolicyStoreException;
import org.globus.security.SigningPolicyStoreParameters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileBasedSigningPolicyStore extends SigningPolicyStore {

    Map<String, FileBasedSigningPolicy> signingPolicyFileMap =
            new HashMap<String, FileBasedSigningPolicy>();
    Map<X500Principal, SigningPolicy> policyMap =
            new HashMap<X500Principal, SigningPolicy>();

    FileSigningPolicyStoreParameters parameters;

    private static Logger logger =
            LoggerFactory.getLogger(FileBasedSigningPolicyStore.class.getName());

    public FileBasedSigningPolicyStore(SigningPolicyStoreParameters param)
            throws InvalidAlgorithmParameterException {
        super(param);
        if (param == null) {
            throw new IllegalArgumentException();
        }

        if (!(param instanceof FileSigningPolicyStoreParameters)) {
            throw new InvalidAlgorithmParameterException();

        }

        this.parameters = (FileSigningPolicyStoreParameters) param;
    }

    public SigningPolicy getSigningPolicy(X500Principal caPrincipal)
            throws SigningPolicyStoreException {

        if (caPrincipal == null) {
            return null;
        }
        loadPolicies();
        return this.policyMap.get(caPrincipal);
    }

    private void loadPolicies() throws SigningPolicyStoreException {

        String[] locations = this.parameters.getTrustRootLocations();

        File file;
        FilenameFilter policyFilter =
                FileBasedSigningPolicy.getSigningPolicyFilter();

        Map<X500Principal, SigningPolicy> newPolicyMap =
                new HashMap<X500Principal, SigningPolicy>();
        Map<String, FileBasedSigningPolicy> newPolicyFileMap =
                new HashMap<String, FileBasedSigningPolicy>();

        for (String location : locations) {

            file = new File(location.trim());

            if (!file.canRead()) {
                logger.debug("Cannot read: " + file.getAbsolutePath());
                continue;
            }

            if (file.isDirectory()) {
                String[] policyFiles = file.list(policyFilter);
                if (policyFiles == null) {
                    logger.debug("Cannot load signing policy from " +
                            file.getAbsolutePath() + " directory.");
                } else {
                    logger.debug("Loading signing policy from " +
                            file.getAbsolutePath() + " directory.");
                    for (String policyFile : policyFiles) {
                        String policyFilename = file.getPath() +
                                File.separatorChar +
                                policyFile;

                        loadSigningPolicy(policyFilename, newPolicyMap,
                                newPolicyFileMap);
                    }
                }
            } else {
                String filename = file.getAbsolutePath();
                if (policyFilter.accept(null, filename)) {
                    loadSigningPolicy(filename, newPolicyMap,
                            newPolicyFileMap);
                }
            }
        }

        this.policyMap = newPolicyMap;
        this.signingPolicyFileMap = newPolicyFileMap;
    }

    private void loadSigningPolicy(String policyFilename,
                                   Map<X500Principal, SigningPolicy> policyMap_,
                                   Map<String, FileBasedSigningPolicy> policyFileMap_)
            throws SigningPolicyStoreException {

        File policyFile = new File(policyFilename);
        if (!policyFile.canRead()) {
            throw new SigningPolicyStoreException("Cannot read file");
        }

        FileBasedSigningPolicy filePolicy =
                this.signingPolicyFileMap
                        .get(policyFilename);
        if (filePolicy == null) {
            try {
                filePolicy = new FileBasedSigningPolicy(new File(policyFilename));
            } catch (FileStoreException e) {
                throw new SigningPolicyStoreException(e);
            }

        }
        Collection<SigningPolicy> policies = filePolicy.getSigningPolicies();

        policyFileMap_.put(policyFilename, filePolicy);
        if (policies != null) {
            for (SigningPolicy policy : policies) {
                policyMap_.put(policy.getCASubjectDN(), policy);
            }
        }
    }
}