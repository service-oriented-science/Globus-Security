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

import org.globus.security.SigningPolicy;
import org.globus.security.SigningPolicyException;
import org.globus.security.SigningPolicyStoreException;
import org.globus.security.util.SigningPolicyFileParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collection;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 28, 2009
 * Time: 2:57:09 PM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceSigningPolicy {
    protected Resource resource;

    private Logger logger = LoggerFactory.getLogger(ResourceSigningPolicy.class.getName());
    private boolean changed;
    private Map<X500Principal, SigningPolicy> signingPolicyMap;
    private long lastModified = -1;

    public ResourceSigningPolicy(Resource resource) throws ResourceStoreException {
        init(resource);
    }

    protected void init(Resource initResource) throws ResourceStoreException {
        this.resource = initResource;
        this.signingPolicyMap = create(this.resource);
        logger.debug("Loading initResource: {}", this.resource.toString());
        try {
            this.lastModified = this.resource.lastModified();
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
    }

    protected void init(Resource initResource, Map<X500Principal, SigningPolicy> initSigningPolicy)
            throws ResourceStoreException {
        if (initSigningPolicy == null) {
            // FIXME: better exception?
            throw new IllegalArgumentException("Object cannot be null");
        }
        this.signingPolicyMap = initSigningPolicy;
        this.resource = initResource;
    }

    public Collection<SigningPolicy> getSigningPolicies()
            throws SigningPolicyStoreException {

        try {
            Map<X500Principal, SigningPolicy> object = getObject();
            if (object != null) {
                return object.values();
            }
        } catch (ResourceStoreException e) {
            throw new SigningPolicyStoreException(e);
        }
        return null;
    }

    public Map<X500Principal, SigningPolicy> create(Resource signingPolicyResource) throws ResourceStoreException {
        SigningPolicyFileParser parser = new SigningPolicyFileParser();
        Map<X500Principal, SigningPolicy> policies;
        try {
            policies = parser.parse(new InputStreamReader(signingPolicyResource.getInputStream()));
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        } catch (SigningPolicyException e) {
            throw new ResourceStoreException(e);
        }

        return policies;
    }


    protected void reload() throws ResourceStoreException {

        this.changed = false;
        long latestLastModified;
        try {
            latestLastModified = this.resource.lastModified();
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
        if (this.lastModified < latestLastModified) {
            this.signingPolicyMap = create(this.resource);
            this.lastModified = latestLastModified;
            this.changed = true;
        }
    }

    public Resource getResource() {
        return this.resource;
    }

    protected Map<X500Principal, SigningPolicy> getObject() throws ResourceStoreException {
        reload();
        return this.signingPolicyMap;
    }

    public boolean hasChanged() {
        return this.changed;
    }
}
