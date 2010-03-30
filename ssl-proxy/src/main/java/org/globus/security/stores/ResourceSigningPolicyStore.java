/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
package org.globus.security.stores;

import java.io.IOException;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.globus.security.SigningPolicy;
import org.globus.security.provider.SigningPolicyStore;
import org.globus.security.provider.SigningPolicyStoreException;
import org.globus.security.provider.SigningPolicyStoreParameters;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class ResourceSigningPolicyStore implements SigningPolicyStore {
    private PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();


    private Map<URI, ResourceSigningPolicy> signingPolicyFileMap = new HashMap<URI, ResourceSigningPolicy>();
    private Map<X500Principal, SigningPolicy> policyMap = new HashMap<X500Principal, SigningPolicy>();

    private ResourceSigningPolicyStoreParameters parameters;

    private Logger logger = Logger.getLogger(ResourceSigningPolicyStore.class.getCanonicalName());

    public ResourceSigningPolicyStore(SigningPolicyStoreParameters param) throws InvalidAlgorithmParameterException {
        if (param == null) {
            throw new IllegalArgumentException();
        }

        if (!(param instanceof ResourceSigningPolicyStoreParameters)) {
            throw new InvalidAlgorithmParameterException();

        }

        this.parameters = (ResourceSigningPolicyStoreParameters) param;
    }

    public SigningPolicy getSigningPolicy(X500Principal caPrincipal) throws SigningPolicyStoreException {

        if (caPrincipal == null) {
            return null;
        }
        loadPolicies();
        return this.policyMap.get(caPrincipal);
    }

    private void loadPolicies() throws SigningPolicyStoreException {

        String locations = this.parameters.getTrustRootLocations();
        Resource[] resources;

        try {
            resources = resolver.getResources(locations);
        } catch (IOException e) {
            throw new SigningPolicyStoreException(e);
        }
        Map<X500Principal, SigningPolicy> newPolicyMap =
                new HashMap<X500Principal, SigningPolicy>();
        Map<URI, ResourceSigningPolicy> newPolicyFileMap =
                new HashMap<URI, ResourceSigningPolicy>();

        for (Resource resource : resources) {

            if (!resource.isReadable()) {
                logger.fine("Cannot read: " + resource.getFilename());
                continue;
            }
            loadSigningPolicy(resource, newPolicyMap, newPolicyFileMap);
        }

        this.policyMap = newPolicyMap;
        this.signingPolicyFileMap = newPolicyFileMap;
    }

    private void loadSigningPolicy(
            Resource policyResource, Map<X500Principal, SigningPolicy> policyMapToLoad,
            Map<URI, ResourceSigningPolicy> currentPolicyFileMap) throws SigningPolicyStoreException {

        URI uri;
        if (!policyResource.isReadable()) {
            throw new SigningPolicyStoreException("Cannot read file");
        }
        try {
            uri = policyResource.getURI();
        } catch (IOException e) {
            throw new SigningPolicyStoreException(e);
        }

        ResourceSigningPolicy filePolicy = this.signingPolicyFileMap.get(uri);
        if (filePolicy == null) {
            try {
                filePolicy = new ResourceSigningPolicy(policyResource);
            } catch (ResourceStoreException e) {
                throw new SigningPolicyStoreException(e);
            }
        }
        Collection<SigningPolicy> policies = filePolicy.getSigningPolicies();

        currentPolicyFileMap.put(uri, filePolicy);
        if (policies != null) {
            for (SigningPolicy policy : policies) {
                policyMapToLoad.put(policy.getCASubjectDN(), policy);
            }
        }
    }
}
