package org.globus.security.resources;

import java.security.cert.CertStoreParameters;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 1:06:39 PM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceCertStoreParameters implements CertStoreParameters {

    private String locationPattern;
    private String[] locations;

    public ResourceCertStoreParameters() {
    }

    public ResourceCertStoreParameters(String locationPattern) {
        this.locationPattern = locationPattern;
    }

    public ResourceCertStoreParameters(String... locations){
        this.locations = locations;
    }

    public String[] getLocations() {
        return locations;
    }

    public String getLocationPattern() {
        return locationPattern;
    }

    public void setLocationPattern(String locationPattern) {
        this.locationPattern = locationPattern;
    }

    /**
     * Makes a copy of this <code>CertStoreParameters</code>.
     * <p/>
     * The precise meaning of "copy" may depend on the class of the
     * <code>CertStoreParameters</code> object. A typical implementation
     * performs a "deep copy" of this object, but this is not an absolute
     * requirement. Some implementations may perform a "shallow copy" of some or
     * all of the fields of this object.
     * <p/>
     * Note that the <code>CertStore.getInstance</code> methods make a copy of
     * the specified <code>CertStoreParameters</code>. A deep copy
     * implementation of <code>clone</code> is safer and more robust, as it
     * prevents the caller from corrupting a shared <code>CertStore</code> by
     * subsequently modifying the contents of its initialization parameters.
     * However, a shallow copy implementation of <code>clone</code> is more
     * appropriate for applications that need to hold a reference to a parameter
     * contained in the <code>CertStoreParameters</code>. For example, a shallow
     * copy clone allows an application to release the resources of a particular
     * <code>CertStore</code> initialization parameter immediately, rather than
     * waiting for the garbage collection mechanism. This should be done with
     * the utmost care, since the <code>CertStore</code> may still be in use by
     * other threads.
     * <p/>
     * Each subclass should state the precise behavior of this method so that
     * users and developers know what to expect.
     *
     * @return a copy of this <code>CertStoreParameters</code>
     */
    public Object clone() {
        return null;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

}
