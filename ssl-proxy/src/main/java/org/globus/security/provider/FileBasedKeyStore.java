package org.globus.security.provider;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

import org.globus.security.CredentialException;
import org.globus.security.X509Credential;
import org.globus.security.filestore.FileBasedKeyStoreParameters;

import org.globus.security.resources.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import static org.globus.security.util.CertificateIOUtil.writeCertificate;


/**
 * This class provides a KeyStore implementation that supports trusted certificates stored in PEM format and proxy
 * certificates stored in PEM format. It reads trusted certificates from multiple directories and a proxy certificate
 * from a file.
 */
public class FileBasedKeyStore extends KeyStoreSpi {

    private static Logger logger =
            LoggerFactory.getLogger(FileBasedKeyStore.class.getName());

    // Default trusted certificates directory
    public static final String DEFAULT_DIRECTORY_KEY = "default_directory";
    // List of directory names to load certificates from
    // FIXME: does it take certificate file names in this list?
    public static final String DIRECTORY_LIST_KEY = "directory_list";
    // X.509 Certificate file name, should be set along with KEY_FILENAME
    public static final String CERTIFICATE_FILENAME = "certificateFilename";
    // Key, typically private key, accompanying the certificate
    public static final String KEY_FILENAME = "keyFilename";
    // X.509 PRoxy Cerificate file name
    public static final String PROXY_FILENAME = "proxyFilename";

    // Map from alias to the object (either key or certificate)
    private Map<String, SecurityObjectWrapper<?>> aliasObjectMap =
            new Hashtable<String, SecurityObjectWrapper<?>>();
    // Map from trusted certificate to filename
    private Map<Certificate, String> certFilenameMap =
            new HashMap<Certificate, String>();

    // default directory for trusted certificates
    private File defaultDirectory;
    private ResourceSecurityWrapperStore<ResourceTrustAnchor, TrustAnchor> caDelegate =
            new ResourceCACertStore();
    private ResourceSecurityWrapperStore<ResourceProxyCredential, X509Credential> proxyDelegate =
            new ResourceProxyCredentialStore();

    @SuppressWarnings("unused")
    public void setCACertStore(ResourceSecurityWrapperStore<ResourceTrustAnchor, TrustAnchor> caDelegate) {
        this.caDelegate = caDelegate;
    }

    @SuppressWarnings("unused")
    public void setProxyDelegate(ResourceSecurityWrapperStore<ResourceProxyCredential, X509Credential> proxyDelegate) {
        this.proxyDelegate = proxyDelegate;
    }

    private CredentialWrapper getKeyEntry(String alias) {

        SecurityObjectWrapper<?> object = this.aliasObjectMap.get(alias);
        if ((object != null) &&
                (object instanceof CredentialWrapper)) {
            return (CredentialWrapper) object;
        }
        return null;
    }


    private ResourceTrustAnchor getCertificateEntry(String alias) {

        SecurityObjectWrapper<?> object = this.aliasObjectMap.get(alias);
        if ((object != null) &&
                (object instanceof ResourceTrustAnchor)) {
            return (ResourceTrustAnchor) object;
        }
        return null;
    }

    @Override
    public Key engineGetKey(String s, char[] chars)
            throws NoSuchAlgorithmException, UnrecoverableKeyException {

        CredentialWrapper credential = getKeyEntry(s);
        Key key = null;
        if (credential != null) {
            try {
                String password = null;
                if (chars != null) {
                    password = new String(chars);
                }
                key = credential.getCredential().getPrivateKey(password);
            } catch (ResourceStoreException e) {
                throw new UnrecoverableKeyException(e.getMessage());
            } catch (CredentialException e) {
                throw new UnrecoverableKeyException(e.getMessage());
            }
        }
        return key;
    }

    @Override
    public boolean engineIsKeyEntry(String s) {
        return (getKeyEntry(s) != null);
    }

    @Override
    public void engineStore(OutputStream outputStream, char[] chars) throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException {
        for (SecurityObjectWrapper<?> object : this.aliasObjectMap.values()) {
            if (object instanceof Storable) {
                try {
                    ((Storable) object).store();
                } catch (ResourceStoreException e) {
                    throw new CertificateException(e);
                }
            }
        }
    }

    @Override
    public Date engineGetCreationDate(String s) {
        try {
            ResourceTrustAnchor trustAnchor = getCertificateEntry(s);
            if (trustAnchor != null) {
                return trustAnchor.getTrustAnchor().
                        getTrustedCert().getNotBefore();
            } else {
                CredentialWrapper credential = getKeyEntry(s);
                if (credential != null) {
                    return credential.getCredential().getNotBefore();
                }
            }
        } catch (ResourceStoreException e) {
            return null;
        }
        return null;
    }

    @Override
    public String engineGetCertificateAlias(Certificate certificate) {
        return this.certFilenameMap.get(certificate);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String s) {
        CredentialWrapper credential = getKeyEntry(s);
        X509Certificate[] chain = null;
        if (credential != null) {
            try {
                chain = credential.getCredential().getCertificateChain();
            } catch (ResourceStoreException e) {
                logger.warn(e.getMessage());
                chain = null;
            }
        }
        return chain;
    }

    @Override
    public Certificate engineGetCertificate(String s) {
        ResourceTrustAnchor trustAnchor = getCertificateEntry(s);
        if (trustAnchor != null) {
            try {
                return trustAnchor.getTrustAnchor().getTrustedCert();
            } catch (ResourceStoreException e) {
                return null;
            }
        }
        return null;
    }

    @Override
    public void engineLoad(KeyStore.LoadStoreParameter loadStoreParameter)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        if (!(loadStoreParameter instanceof FileBasedKeyStoreParameters)) {
            throw new IllegalArgumentException(
                    "Unable to process parameters: " + loadStoreParameter);
        }
        FileBasedKeyStoreParameters params = (FileBasedKeyStoreParameters) loadStoreParameter;
        String defaultDirectoryString = params.getDefaultCertDir();
        String directoryListString = params.getCertDirs();
        String certFilename = params.getUserCertFilename();
        String keyFilename = params.getUserKeyFilename();
        String proxyFilename = params.getProxyFilename();
        initialize(defaultDirectoryString, directoryListString, proxyFilename, certFilename, keyFilename);
    }

    @Override
    public void engineLoad(InputStream inputStream, char[] chars)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        try {
            Properties properties = new Properties();
            properties.load(inputStream);
            if (properties.size() == 0) {
                throw new CertificateException("Properties file for configuration was null");
            }
            String defaultDirectoryString = properties.getProperty(DEFAULT_DIRECTORY_KEY);
            String directoryListString = properties.getProperty(DIRECTORY_LIST_KEY);
            String proxyFilename = properties.getProperty(PROXY_FILENAME);
            String certFilename = properties.getProperty(CERTIFICATE_FILENAME);
            String keyFilename = properties.getProperty(KEY_FILENAME);
            initialize(defaultDirectoryString, directoryListString, proxyFilename, certFilename, keyFilename);
        } finally {
            try {
                inputStream.close();
            } catch (IOException e) {
                logger.info("Error closing inputStream", e);
            }
        }
    }

    private void initialize(String defaultDirectoryString, String directoryListString, String proxyFilename, String certFilename, String keyFilename) throws IOException, CertificateException {
        if (defaultDirectoryString != null) {
            defaultDirectory = new File(defaultDirectoryString.substring(0, defaultDirectoryString.lastIndexOf(File.pathSeparator)));
            if (!defaultDirectory.exists()) {
                boolean directoryMade = defaultDirectory.mkdirs();
                if (!directoryMade) {
                    throw new IOException(
                            "Unable to create default certificate directory");
                }
            }
            try {
                loadDirectories(defaultDirectoryString);
            } catch (ResourceStoreException e) {
                throw new CertificateException(e);
            }
        }
        if (directoryListString != null) {
            try {
//                String[] directoryList = directoryListString.split(",");
                loadDirectories(directoryListString);
            } catch (ResourceStoreException e) {
                throw new CertificateException(e);
            }
        }
        try {
            if (proxyFilename != null) {
                loadProxyCertificate(proxyFilename);
            }
            if ((certFilename != null) &&
                    (keyFilename != null)) {
                loadCertificateKey(certFilename, keyFilename);
            }
        } catch (ResourceStoreException e) {
            throw new CertificateException(e);
        } catch (CredentialException e) {
            e.printStackTrace();
            throw new CertificateException(e);
        }
    }

    private void loadProxyCertificate(String proxyFilename) throws ResourceStoreException {

        if (proxyFilename == null) {
            return;
        }

        proxyDelegate.loadWrappers(proxyFilename);
        Map<String, ResourceProxyCredential> wrapperMap =
                proxyDelegate.getWrapperMap();
        for (ResourceProxyCredential credential : wrapperMap.values()) {
            this.aliasObjectMap.put(proxyFilename, credential);
        }
    }


    private void loadCertificateKey(String userCertFilename, String userKeyFilename)
            throws CredentialException, ResourceStoreException {
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();

        if ((userCertFilename == null) ||
                (userKeyFilename == null)) {
            return;
        }
//        File certFile = new File(userCertFilename);
//        File keyFile = new File(userKeyFilename);
        Resource certResource = resolver.getResource(userCertFilename);
        Resource keyResource = resolver.getResource(userKeyFilename);
        CertKeyCredential credential = new CertKeyCredential(certResource, keyResource);
        // What do we name this alias?
        String alias = userCertFilename + ":" + userKeyFilename;
        this.aliasObjectMap.put(alias, credential);
    }


    private void loadDirectories(String directoryList)
            throws ResourceStoreException {

        caDelegate.loadWrappers(directoryList);
        Map<String, ResourceTrustAnchor> wrapperMap = caDelegate.getWrapperMap();
        for (ResourceTrustAnchor trustAnchor : wrapperMap
                .values()) {
            String alias = trustAnchor.getFile().getName();
            certFilenameMap
                    .put(trustAnchor.getTrustAnchor().getTrustedCert(),
                            alias);
            this.aliasObjectMap.put(alias, trustAnchor);
        }
    }

    @Override
    public void engineDeleteEntry(String s) throws KeyStoreException {

        SecurityObjectWrapper<?> object = this.aliasObjectMap.remove(s);
        if (object != null) {
            if (object instanceof ResourceTrustAnchor) {

                ResourceTrustAnchor descriptor = (ResourceTrustAnchor) object;
                Certificate cert;
                try {
                    cert = descriptor.getTrustAnchor().getTrustedCert();
                } catch (ResourceStoreException e) {
                    throw new KeyStoreException(e);
                }
                this.certFilenameMap.remove(cert);
                boolean success = descriptor.getFile().delete();
                if (!success) {
                    // FIXME: warn? throw error?
                    logger.info("Unable to delete certificate");
                }
            } else if (object instanceof ResourceProxyCredential) {

                ResourceProxyCredential proxy = (ResourceProxyCredential) object;
                try {
                    proxy.getCredential();
                } catch (ResourceStoreException e) {
                    throw new KeyStoreException(e);
                }
                boolean success = proxy.getFile().delete();
                if (!success) {
                    // FIXME: warn? throw error?
                    logger.info("Unable to delete credential");
                }
            }
        }
    }

    @Override
    public Enumeration<String> engineAliases() {

        return Collections.enumeration(this.aliasObjectMap.keySet());
    }

    @Override
    public void engineSetKeyEntry(String s, Key key, char[] chars, Certificate[] certificates)
            throws KeyStoreException {

        if (!(key instanceof PrivateKey)) {
            throw new KeyStoreException("PrivateKey expected");
        }

        if (!(certificates instanceof X509Certificate[])) {
            throw new KeyStoreException("Certificate chain of X509Certificate expected");
        }
        CredentialWrapper wrapper;
        X509Credential credential = new X509Credential((PrivateKey) key, (X509Certificate[]) certificates);
        Resource certResource;
        Resource keyResource;
        if (credential.isEncryptedKey()) {
            CredentialWrapper credentialWrapper = getKeyEntry(s);
            if(credentialWrapper != null && credentialWrapper instanceof CertKeyCredential){
                CertKeyCredential certKeyCred = (CertKeyCredential) credentialWrapper;
                certResource = certKeyCred.getCertificateFile();
                keyResource = certKeyCred.getKeyFile();
            } else {
                certResource = new FileSystemResource(new File(defaultDirectory, s + ".0"));
                keyResource = new FileSystemResource(new File(defaultDirectory, s + "-key.pem"));
            }
            try {
                wrapper = new CertKeyCredential(certResource, keyResource, credential);
            } catch (ResourceStoreException e) {
                throw new KeyStoreException(e);
            }
        } else {
            CredentialWrapper proxyCredential = getKeyEntry(s);
            File file;
            if (proxyCredential != null && proxyCredential instanceof AbstractResourceSecurityWrapper) {
                AbstractResourceSecurityWrapper proxyWrapper = (AbstractResourceSecurityWrapper) proxyCredential;
                file = proxyWrapper.getFile();
            } else {
                // FIXME: should alias be file name? or generate?
                file = new File(defaultDirectory, s + "-key.pem");
            }
            try {
                wrapper = new ResourceProxyCredential(new FileSystemResource(file), credential);
            } catch (ResourceStoreException e) {
                throw new KeyStoreException(e);
            }
        }
        try {
            wrapper.store();
            this.aliasObjectMap.put(wrapper.getAlias(), wrapper);
        } catch (ResourceStoreException e) {
            throw new KeyStoreException("Error storing credential", e);
        }

    }

    @Override
    public void engineSetKeyEntry(String s, byte[] bytes, Certificate[] certificates)
            throws KeyStoreException {
        throw new UnsupportedOperationException();
        // FIXME
    }

    @Override
    public boolean engineContainsAlias(String s) {
        return this.aliasObjectMap.containsKey(s);
    }

    @Override
    public int engineSize() {
        return this.aliasObjectMap.size();
    }

    @Override
    public boolean engineIsCertificateEntry(String s) {
        return (getCertificateEntry(s) != null);
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate certificate)
            throws KeyStoreException {

        if (!(certificate instanceof X509Certificate)) {
            throw new KeyStoreException("Certificate must be instance of X509Certificate");
        }
        File file;
        ResourceTrustAnchor trustAnchor = getCertificateEntry(alias);
        if (trustAnchor != null) {
            file = trustAnchor.getFile();
        } else {
            file = new File(defaultDirectory, alias);
        }
        X509Certificate x509Cert = (X509Certificate) certificate;
        try {
            writeCertificate(x509Cert, file);
            ResourceTrustAnchor anchor = new ResourceTrustAnchor(new FileSystemResource(file), new TrustAnchor(
                    x509Cert, null));
            this.aliasObjectMap.put(alias, anchor);
            this.certFilenameMap.put(x509Cert, alias);
        } catch (ResourceStoreException e) {
            throw new KeyStoreException(e);
        } catch (IOException e) {
            throw new KeyStoreException(e);
        } catch (CertificateEncodingException e) {
            throw new KeyStoreException(e);
        }
    }

}
