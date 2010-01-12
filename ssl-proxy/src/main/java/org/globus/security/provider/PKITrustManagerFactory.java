package org.globus.security.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Collection;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

import org.globus.security.X509ProxyCertPathParameters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Oct 14, 2009 Time: 2:38:28
 * PM To change this template use File | Settings | File Templates.
 */
public class PKITrustManagerFactory extends TrustManagerFactorySpi {

    private Collection<TrustManager> trustManagers =
        new ArrayList<TrustManager>();
    private Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    protected void engineInit(KeyStore keyStore) throws KeyStoreException {
        logger.debug("Initializing engine with KeyStore only");
        try {
            this.engineInit(
                new CertPathTrustManagerParameters(
                    new X509ProxyCertPathParameters(keyStore, null, null,
                        false)));
        } catch (InvalidAlgorithmParameterException e) {
            throw new KeyStoreException(e);
        }
    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters)
        throws InvalidAlgorithmParameterException {
        if (managerFactoryParameters instanceof X509ProxyCertPathParameters) {
            X509ProxyCertPathParameters ptmfp =
                (X509ProxyCertPathParameters) managerFactoryParameters;
            trustManagers.add(
                new PKITrustManager(new X509ProxyCertPathValidator(), ptmfp));
        }

    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        return trustManagers
            .toArray(new TrustManager[trustManagers.size()]);
    }
}
