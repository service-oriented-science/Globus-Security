package org.globus.security.resources;

import org.globus.security.util.CertificateIOUtil;
import org.globus.security.util.CertificateLoadUtil;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 11:37:52 AM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceTrustAnchor extends AbstractResourceSecurityWrapper<TrustAnchor> {


    public ResourceTrustAnchor(String fileName) throws ResourceStoreException {
        init(resolver.getResource(fileName));
    }

    public ResourceTrustAnchor(Resource resource) throws ResourceStoreException {
        init(resource);
    }

    public ResourceTrustAnchor(String fileName, TrustAnchor cachedAnchor) throws ResourceStoreException {
        init(resolver.getResource(fileName), cachedAnchor);
    }

    public ResourceTrustAnchor(Resource resource, TrustAnchor cachedAnchor) throws ResourceStoreException {
        init(resource, cachedAnchor);
    }

    public TrustAnchor getTrustAnchor() throws ResourceStoreException {
        return super.getSecurityObject();
    }

    @Override
    protected TrustAnchor create(Resource resource) throws ResourceStoreException {
        X509Certificate certificate;
        try {
            certificate = CertificateLoadUtil.loadCertificate(resource.getInputStream());
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        } catch (GeneralSecurityException e) {
            throw new ResourceStoreException(e);
        }

        return new TrustAnchor(certificate, null);
    }

    public void store() throws ResourceStoreException {
        try {
            CertificateIOUtil.writeCertificate(this.getTrustAnchor().getTrustedCert(), resource.getFile());
        } catch (CertificateEncodingException e) {
            throw new ResourceStoreException(e);
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
    }
}
