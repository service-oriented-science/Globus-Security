package org.globus.security.resources;

import org.springframework.core.io.Resource;

import java.io.File;
import java.net.URL;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 6, 2010
 * Time: 10:14:05 AM
 * To change this template use File | Settings | File Templates.
 */
public interface SecurityObjectWrapper<T> {
    void refresh() throws ResourceStoreException;

    T getSecurityObject() throws ResourceStoreException;

    String getAlias();

    boolean hasChanged();
}
