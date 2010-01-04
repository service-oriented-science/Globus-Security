package org.globus.security.resources;

import org.globus.security.SigningPolicy;
import org.globus.security.SigningPolicyException;
import org.globus.security.SigningPolicyStoreException;
import org.globus.security.filestore.FileStoreException;
import org.globus.security.util.SigningPolicyFileParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import javax.security.auth.x500.X500Principal;
import java.io.*;
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
    private static Logger logger =
            LoggerFactory.getLogger(ResourceSigningPolicy.class.getName());

    private boolean changed;
    private Map<X500Principal, SigningPolicy> signingPolicyMap;
    private long lastModified = -1;

    protected Resource resource = null;

    public ResourceSigningPolicy(Resource resource) throws ResourceStoreException {
        init(resource);
    }

    protected void init(Resource resource) throws ResourceStoreException {
        this.resource = resource;
        this.signingPolicyMap = create(this.resource);
        logger.debug("Loading resource: {}", this.resource.toString());
        try {
            this.lastModified = this.resource.lastModified();
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
    }

    protected void init(Resource resource, Map<X500Principal, SigningPolicy> signingPolicyMap) throws ResourceStoreException {
        if (signingPolicyMap == null) {
            // FIXME: better exception?
            throw new IllegalArgumentException("Object cannot be null");
        }
        this.signingPolicyMap = signingPolicyMap;
        this.resource = resource;
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

    public Map<X500Principal, SigningPolicy> create(Resource resource) throws ResourceStoreException {
        SigningPolicyFileParser parser = new SigningPolicyFileParser();
        Map<X500Principal, SigningPolicy> policies;
        try {
            policies = parser.parse(new InputStreamReader(resource.getInputStream()));
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
