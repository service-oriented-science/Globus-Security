package org.globus.security.resources;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.File;
import java.io.IOException;
import java.net.URL;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 12:35:50 PM
 * To change this template use File | Settings | File Templates.
 */
public abstract class AbstractResourceSecurityWrapper<T> implements SecurityObjectWrapper<T>, Storable {
    Logger logger = LoggerFactory.getLogger(getClass());
    private boolean changed;
    private T securityObject;
    private long lastModified = -1;
    protected Resource resource = null;
    protected PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();

    protected void init(String locationPattern) throws ResourceStoreException{
        init(resolver.getResource(locationPattern));
    }

    protected void init(Resource resource) throws ResourceStoreException {
        this.resource = resource;
        this.securityObject = create(this.resource);
        logger.debug("Loading resource: {}", this.resource.toString());
        try {
            this.lastModified = this.resource.lastModified();
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
    }

    protected void init(String locationPattern, T securityObject) throws ResourceStoreException{
        init(resolver.getResource(locationPattern), securityObject);
    }

    protected void init(Resource resource, T securityObject) throws ResourceStoreException {
        if (securityObject == null) {
            // FIXME: better exception?
            throw new IllegalArgumentException("Object cannot be null");
        }
        this.securityObject = securityObject;
        this.resource = resource;
    }

    public Resource getResource() {
        return resource;
    }

    public URL getResourceURL(){
        try {
            return resource.getURL();
        } catch (IOException e) {
            logger.warn("Unable to extract url", e);
            return null;
        }
    }

    public File getFile(){
        try {
            return resource.getFile();
        } catch (IOException e) {
            logger.debug("Resource is not a file", e);
            return null;
        }
    }

    public void refresh() throws ResourceStoreException {
        this.changed = false;
        long latestLastModified;
        try {
            latestLastModified = this.resource.lastModified();
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
        if (this.lastModified < latestLastModified) {
            this.securityObject = create(this.resource);
            this.lastModified = latestLastModified;
            this.changed = true;
        }
    }

    protected abstract T create(Resource resource) throws ResourceStoreException;

    public T getSecurityObject() throws ResourceStoreException {
        refresh();
        return this.securityObject;
    }

    public boolean hasChanged(){
        return this.changed;
    }
}
