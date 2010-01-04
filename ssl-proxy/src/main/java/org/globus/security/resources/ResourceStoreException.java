package org.globus.security.resources;

import java.security.GeneralSecurityException;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 9:25:02 AM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceStoreException extends GeneralSecurityException {
    public ResourceStoreException() {
    }

    public ResourceStoreException(String s) {
        super(s);
    }

    public ResourceStoreException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public ResourceStoreException(Throwable throwable) {
        super(throwable);
    }
}
