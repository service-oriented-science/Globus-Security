package org.globus.security.filestore;

import java.security.KeyStore;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Oct 14, 2009
 * Time: 3:54:08 PM
 * To change this template use File | Settings | File Templates.
 */
public class FileBasedKeyStoreParameters implements KeyStore.LoadStoreParameter{
    private String[] certDirs;
    private String defaultCertDir;

    public FileBasedKeyStoreParameters() {
    }

    public FileBasedKeyStoreParameters(String[] certDirs, String defaultCertDir) {
        this.certDirs = certDirs;
        this.defaultCertDir = defaultCertDir;
    }

    public KeyStore.ProtectionParameter getProtectionParameter() {
        return null;
    }

    public String[] getCertDirs() {
        return certDirs;
    }

    public void setCertDirs(String[] certDirs) {
        this.certDirs = certDirs;
    }

    public String getDefaultCertDir() {
        return defaultCertDir;
    }

    public void setDefaultCertDir(String defaultCertDir) {
        this.defaultCertDir = defaultCertDir;
    }
}
