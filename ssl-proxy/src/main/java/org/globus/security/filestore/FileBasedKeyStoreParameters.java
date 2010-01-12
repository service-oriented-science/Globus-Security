package org.globus.security.filestore;

import java.security.KeyStore;

/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Oct 14, 2009 Time: 3:54:08
 * PM To change this template use File | Settings | File Templates.
 */
public class FileBasedKeyStoreParameters
    implements KeyStore.LoadStoreParameter {

    private String certDirs;
    private String defaultCertDir;
    private String userCertFilename;
    private String userKeyFilename;
    private KeyStore.ProtectionParameter protectionParameter;
    private String proxyFilename;

    public FileBasedKeyStoreParameters() {
    }

    public FileBasedKeyStoreParameters(
        String certDirs,
        String defaultCertDir) {
        this.certDirs = certDirs;
        this.defaultCertDir = defaultCertDir;

    }

    public FileBasedKeyStoreParameters(
        String initCertDirs, String initDefaultCertDir, String initUserCertFileName,
        String initUserKeyFileName, KeyStore.ProtectionParameter initProtectionParameter) {
        this(initCertDirs, initDefaultCertDir);
        this.userCertFilename = initUserCertFileName;
        this.userKeyFilename = initUserKeyFileName;
        this.protectionParameter = initProtectionParameter;
    }

    public FileBasedKeyStoreParameters(String initCertDirs, String initDefaultCertDir, String initProxyFileName) {
        this(initCertDirs, initDefaultCertDir);
        this.proxyFilename = initProxyFileName;
    }

    public FileBasedKeyStoreParameters(
        String initCertDirs,
        String initDefaultCertDir,
        String initUserCertFileName,
        String initUserKeyFileName,
        KeyStore.ProtectionParameter initProtectionParameter,
        String initProxyFileName) {
        this(initCertDirs, initDefaultCertDir, initUserCertFileName, initUserKeyFileName,
            initProtectionParameter);
        this.proxyFilename = initProxyFileName;
    }

    public KeyStore.ProtectionParameter getProtectionParameter() {
        return this.protectionParameter;
    }

    public String getCertDirs() {
        return certDirs;
    }

    public void setCertDirs(String certDirs) {
        this.certDirs = certDirs;
    }

    public String getDefaultCertDir() {
        return defaultCertDir;
    }

    public String getUserCertFilename() {
        return this.userCertFilename;
    }

    public String getUserKeyFilename() {
        return this.userKeyFilename;
    }

    public String getProxyFilename() {
        return this.proxyFilename;
    }

    // Why is this a mutable class?

    public void setDefaultCertDir(String defaultCertDir) {
        this.defaultCertDir = defaultCertDir;
    }
}
