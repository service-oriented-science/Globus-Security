package org.globus.security.filestore;

import java.security.KeyStore;
import java.util.Arrays;

import org.globus.security.util.ArraysUtil;

/**
 * Created by IntelliJ IDEA. User: turtlebender Date: Oct 14, 2009 Time: 3:54:08
 * PM To change this template use File | Settings | File Templates.
 */
public class FileBasedKeyStoreParameters
        implements KeyStore.LoadStoreParameter {

    private String[] certDirs;
    private String defaultCertDir;
    private String userCertFilename;
    private String userKeyFilename;
    private KeyStore.ProtectionParameter protectionParameter;
    private String proxyFilename;

    public FileBasedKeyStoreParameters() {
    }

    public FileBasedKeyStoreParameters(String[] certDirs,
                                       String defaultCertDir) {
        this.certDirs = ArraysUtil.copyArray(String.class, certDirs, certDirs.length);
        this.defaultCertDir = defaultCertDir;

    }

    public FileBasedKeyStoreParameters(String[] certDirs_,
                                       String defaultCertDir_,
                                       String userCertFilename_,
                                       String userKeyFilename_,
                                       KeyStore.ProtectionParameter protectionParameter_) {
        this(certDirs_, defaultCertDir_);
        this.userCertFilename = userCertFilename_;
        this.userKeyFilename = userKeyFilename_;
        this.protectionParameter = protectionParameter_;
    }

    public FileBasedKeyStoreParameters(String[] certDirs_,
                                       String defaultCertDir_,
                                       String proxyFilename_) {
        this(certDirs_, defaultCertDir_);
        this.proxyFilename = proxyFilename_;
    }

    public FileBasedKeyStoreParameters(String[] certDirs_,
                                       String defaultCertDir_,
                                       String userCertFilename_,
                                       String userKeyFilename_,
                                       KeyStore.ProtectionParameter protectionParameter_,
                                       String proxyFilename_) {
        this(certDirs_, defaultCertDir_, userCertFilename_, userKeyFilename_,
                protectionParameter_);
        this.proxyFilename = proxyFilename_;
    }

    public KeyStore.ProtectionParameter getProtectionParameter() {
        return this.protectionParameter;
    }

    public String[] getCertDirs() {
        return ArraysUtil.copyArray(String.class, certDirs, certDirs.length);
    }

    public void setCertDirs(String[] certDirs) {
        this.certDirs = ArraysUtil.copyArray(String.class, certDirs, certDirs.length);
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
