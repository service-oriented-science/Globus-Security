package org.globus.security.resources;

import org.globus.security.util.CertificateIOUtil;
import org.globus.security.util.CertificateLoadUtil;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 12:41:39 PM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceCRL extends AbstractResourceSecurityWrapper<X509CRL> {

    public ResourceCRL(String fileName) throws ResourceStoreException {
        init(resolver.getResource(fileName));
    }

    public ResourceCRL(Resource resource) throws ResourceStoreException {
        init(resource);
    }

    public ResourceCRL(String fileName, X509CRL crl) throws ResourceStoreException {
        init(resolver.getResource(fileName), crl);
    }

    public X509CRL getCrl() throws ResourceStoreException{
        return getSecurityObject();
    }

    @Override
    protected X509CRL create(Resource resource) throws ResourceStoreException {
        try {
            return CertificateLoadUtil.loadCrl(resource.getInputStream());
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        } catch (GeneralSecurityException e) {
            throw new ResourceStoreException(e);
        }
    }

    public void store() throws ResourceStoreException {
        //TODO: does this need an implementation
    }
}
