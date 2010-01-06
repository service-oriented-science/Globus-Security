package org.globus.security.resources;

import java.net.URL;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 6, 2010
 * Time: 1:25:44 PM
 * To change this template use File | Settings | File Templates.
 */
public interface Storable {
    public void store() throws ResourceStoreException;
}
