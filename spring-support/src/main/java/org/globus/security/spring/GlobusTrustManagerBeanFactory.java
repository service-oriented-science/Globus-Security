package org.globus.security.spring;

import org.globus.security.SigningPolicyStore;
import org.globus.security.X509ProxyCertPathParameters;
import org.globus.security.provider.PKITrustManager;
import org.globus.security.provider.X509ProxyCertPathValidator;
import org.springframework.beans.factory.FactoryBean;

import javax.net.ssl.TrustManager;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import java.security.KeyStore;
import java.security.cert.CertStore;

/**
 * Spring FactoryBean for creating a Globus PKITrustManager.
 *
 * @author Tom Howe
 * @since 1.0
 */
public class GlobusTrustManagerBeanFactory implements FactoryBean<TrustManager[]>{
    private KeyStore trustStore;
    private CertStore certStore;
    private SigningPolicyStore signingPolicyStore;



    public TrustManager[] getObject() throws Exception {
        X509ProxyCertPathValidator validator = new X509ProxyCertPathValidator();
        X509ProxyCertPathParameters parameters =
                new X509ProxyCertPathParameters(trustStore, certStore,
                        signingPolicyStore, false);
        TrustManager tm = new PKITrustManager(validator, parameters);
        return new TrustManager[]{tm};
    }

    public Class<? extends TrustManager[]> getObjectType() {
        return PKITrustManager[].class;
    }

    public boolean isSingleton() {
        return true;
    }

    public void setTrustStore(KeyStore trustStore) {
        this.trustStore = trustStore;
    }

    public void setCertStore(CertStore certStore) {
        this.certStore = certStore;
    }

    public void setSigningPolicyStore(SigningPolicyStore signingPolicyStore) {
        this.signingPolicyStore = signingPolicyStore;
    }
}
