package org.globus.security.resources;

/**
 * Fill Me
 *
 * @param <T> The type of security object to be wrapped
 */
public interface SecurityObjectWrapper<T> {
    void refresh() throws ResourceStoreException;

    T getSecurityObject() throws ResourceStoreException;

    String getAlias();

    boolean hasChanged();
}
