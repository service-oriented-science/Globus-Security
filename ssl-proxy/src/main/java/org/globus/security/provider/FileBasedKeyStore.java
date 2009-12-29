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
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

import org.globus.security.X509Credential;
<<<<<<< HEAD
import org.globus.security.filestore.FileBasedCertKeyCredential;
import org.globus.security.filestore.FileBasedCredential;
=======
>>>>>>> a64ce28... filebasedobject rework take1
import org.globus.security.filestore.FileBasedKeyStoreParameters;
import org.globus.security.filestore.FileBasedProxyCredential;
import org.globus.security.filestore.FileBasedStore;
import org.globus.security.filestore.FileBasedTrustAnchor;
import org.globus.security.filestore.FileStoreException;
<<<<<<< HEAD
import org.globus.security.filestore.MultipleFileBasedObject;
=======
>>>>>>> a64ce28... filebasedobject rework take1
import org.globus.security.filestore.SingleFileBasedObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.globus.security.filestore.FileBasedStore.LoadFileType;
import static org.globus.security.util.CertificateIOUtil.writeCertificate;


/**
 * This class provides a KeyStore implementation that supports trusted certificates stored in PEM format and proxy
 * certificates stored in PEM format. It reads trusted certificates from multiple directories and a proxy certificate
 * from a file.
 */
// The FileBasedObject and FileBasedCredential classes need to be revisited. This code needs to be analyzed and improved.
public class FileBasedKeyStore extends KeyStoreSpi {

    private static Logger logger =
            LoggerFactory.getLogger(FileBasedCertStore.class.getName());

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
<<<<<<< HEAD
    private Map<String, FileBasedObject> aliasObjectMap =
            new Hashtable<String, FileBasedObject>();
=======
    private Map<String, SingleFileBasedObject> aliasObjectMap =
            new Hashtable<String, SingleFileBasedObject>();
    // Map from trusted certificate to filename
    private Map<Certificate, String> certFilenameMap =
            new HashMap<Certificate, String>();
    // Map from proxy certificate to filename
    private Map<X509Credential, String> proxyFilenameMap =
            new HashMap<X509Credential, String>();
>>>>>>> a64ce28... filebasedobject rework take1

    // default directory for trusted certificates
    private File defaultDirectory;
    private FileBasedStore caDelegate =
            FileBasedStore.getFileBasedStore(LoadFileType.CA_FILE);

    private FileBasedCredential getKeyEntry(String alias) {

<<<<<<< HEAD
        FileBasedObject object = this.aliasObjectMap.get(alias);
        if ((object != null) && (object instanceof FileBasedCredential)) {

            return (FileBasedCredential) object;
=======
        SingleFileBasedObject object = this.aliasObjectMap.get(alias);
        if ((object != null) &&
                (object instanceof FileBasedProxyCredential)) {
            return (FileBasedProxyCredential) object;
>>>>>>> a64ce28... filebasedobject rework take1
        }
        return null;
    }


    private FileBasedTrustAnchor getCertificateEntry(String alias) {

        SingleFileBasedObject object = this.aliasObjectMap.get(alias);
        if ((object != null) &&
                (object instanceof FileBasedTrustAnchor)) {
            return (FileBasedTrustAnchor) object;
        }
        return null;
    }

    @Override
    public Key engineGetKey(String s, char[] chars)
            throws NoSuchAlgorithmException, UnrecoverableKeyException {

        FileBasedCredential credential = getKeyEntry(s);
        Key key = null;
        if (credential != null) {
            try {
                String password = null;
                if (chars != null) {
                    password = new String(chars);
                }
                key = credential.getCredential().getPrivateKey(password);
            } catch (FileStoreException e) {
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
<<<<<<< HEAD

        for (FileBasedObject object : this.aliasObjectMap.values()) {
=======
        for (SingleFileBasedObject object : this.aliasObjectMap.values()) {
            File file = object.getFile();
>>>>>>> a64ce28... filebasedobject rework take1
            try {
                if (object instanceof FileBasedTrustAnchor) {
                    FileBasedTrustAnchor desc = (FileBasedTrustAnchor) object;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
                    writeCertificate(desc.getTrustAnchor().getTrustedCert(), file);
                } else if (object instanceof FileBasedCredential) {
                    FileBasedCredential credential = (FileBasedCredential) object;
                    credential.storeCredential();
=======
                    if (file == null) {
                        String filename = this.certFilenameMap.get(desc.getTrustAnchor().getTrustedCert());
                        file = new File(this.defaultDirectory, filename + ".0");
                    }
                    writeCertificate(desc.getTrustAnchor().getTrustedCert(), file);
                } else if (object instanceof FileBasedProxyCredential) {
                    FileBasedProxyCredential proxy = (FileBasedProxyCredential) object;
                    X509Credential credential = proxy.getCredential();
                    if (file == null) {
                        String filename = this.proxyFilenameMap.get(credential);
                        file = new File(this.defaultDirectory, filename + ".pem");
                    }
                    credential.writeToFile(file);
>>>>>>> a64ce28... filebasedobject rework take1
=======
                    if (file == null) {
                        // FIXME:
                        //String filename = this.trustedCertFilenameMap.get(desc.getTrustAnchor().getTrustedCert());
                        //file = new File(this.defaultDirectory, filename + ".0");
                    }
                    writeCertificate(desc.getTrustAnchor().getTrustedCert(), file);
=======
                    if (file == null) {
                        // FIXME:
                        //String filename = this.trustedCertFilenameMap.get(desc.getTrustAnchor().getTrustedCert());
                        //file = new File(this.defaultDirectory, filename + ".0");
                    }
                    writeCertificate(desc.getTrustAnchor().getTrustedCert(), file);
>>>>>>> 9675559... Write to file improved. Tests work now.
=======
                    if (file == null) {
                        // FIXME:
                        //String filename = this.trustedCertFilenameMap.get(desc.getTrustAnchor().getTrustedCert());
                        //file = new File(this.defaultDirectory, filename + ".0");
                    }
                    writeCertificate(desc.getTrustAnchor().getTrustedCert(), file);
>>>>>>> 9675559... Write to file improved. Tests work now.
                } else if (object instanceof FileBasedProxyCredential) {
                    FileBasedProxyCredential proxy = (FileBasedProxyCredential) object;
                    File file = proxy.getFile();
                    X509Credential credential = proxy.getCredential();
                    if (file == null) {
                        // String filename = this.certKeyFilenameMap.get(credential);
                        //file = new File(this.defaultDirectory, filename + ".pem");
                    }
                    credential.writeToFile(file);
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> 9675559... Write to file improved. Tests work now.
=======
>>>>>>> 9675559... Write to file improved. Tests work now.
=======
>>>>>>> 9675559... Write to file improved. Tests work now.
                }
            } catch (FileStoreException e) {
                throw new CertificateException(e);
            }
        }
    }

    @Override
    public Date engineGetCreationDate(String s) {
        try {
            FileBasedTrustAnchor trustAnchor = getCertificateEntry(s);
            if (trustAnchor != null) {
                return trustAnchor.getTrustAnchor().
                        getTrustedCert().getNotBefore();
            } else {
                FileBasedCredential credential = getKeyEntry(s);
                if (credential != null) {
                    return credential.getCredential().getNotBefore();
                }
            }
        } catch (FileStoreException e) {
            return null;
        }
        return null;
    }

    @Override
    public String engineGetCertificateAlias(Certificate certificate) {
<<<<<<< HEAD

        // FIXME,
        return null;
=======
        return this.certFilenameMap.get(certificate);
>>>>>>> a64ce28... filebasedobject rework take1
    }

    @Override
    public Certificate[] engineGetCertificateChain(String s) {

        FileBasedCredential credential = getKeyEntry(s);
        X509Certificate[] chain = null;
        if (credential != null) {
            try {
                chain = credential.getCredential().getCertificateChain();
            } catch (FileStoreException e) {
                logger.warn(e.getMessage());
                chain = null;
            }
        }
        return chain;
    }

    @Override
    public Certificate engineGetCertificate(String s) {

        FileBasedTrustAnchor trustAnchor = getCertificateEntry(s);
        if (trustAnchor != null) {
            try {
                return trustAnchor.getTrustAnchor().getTrustedCert();
            } catch (FileStoreException e) {
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
        FileBasedKeyStoreParameters params =
                (FileBasedKeyStoreParameters) loadStoreParameter;
        try {
<<<<<<< HEAD

            // load trusted CAs, if configured
            String[] certs = params.getCertDirs();
            if (certs != null) {
                loadDirectories(certs);
            }

            // load trusted CAs from default location
            String defaultCert = params.getDefaultCertDir();
            if (defaultCert != null) {
                loadDirectories(new String[]{defaultCert});
            }

            // load proxy certificate, if configured
            String proxy = params.getProxyFilename();
            if (proxy != null) {
                loadProxyCertificate(proxy);
            }
            // load usercert/key, if configured
            String userCert = params.getUserCertFilename();
            String userKey = params.getUserKeyFilename();
            if ((userCert != null) && (userKey != null)) {
                loadCertificateKey(userCert, userKey);
            }

=======
            loadDirectories(params.getCertDirs());
            loadDirectories(new String[]{params.getDefaultCertDir()});
            // load proxy certificate, if configured
            loadProxyCertificate(params.getProxyFilename());
>>>>>>> 1cd74b7... Rework X509Credential class to support clear or encrypted private key, and cert/file from separate streams.
        } catch (FileStoreException e) {
            throw new CertificateException(e);
        } catch (CredentialException e) {
            throw new CertificateException(e);
        }


        // load usercert/key, if configured
        loadCertificateKey(params.getUserCertFilename(),
                params.getUserKeyFilename(),
                params.getProtectionParameter());
    }

    @Override
    public void engineLoad(InputStream inputStream, char[] chars)
            throws IOException, NoSuchAlgorithmException, CertificateException {

        try {
            Properties properties = new Properties();
            properties.load(inputStream);
            if (properties == null) {
                throw new CertificateException("Properties file for configuration was null");
            }
            String defaultDirectoryString =
                    properties.getProperty(DEFAULT_DIRECTORY_KEY);
            if (defaultDirectoryString != null) {
                defaultDirectory = new File(defaultDirectoryString);
                if (!defaultDirectory.exists()) {
                    boolean directoryMade = defaultDirectory.mkdirs();
                    if (!directoryMade) {
                        throw new IOException(
                                "Unable to create default certificate directory");
                    }
                } else {
                    try {
                        loadDirectories(new String[]{defaultDirectoryString});
                    } catch (FileStoreException e) {
                        throw new CertificateException(e);
                    }
                }
            }
            String directoryListString =
                    properties.getProperty(DIRECTORY_LIST_KEY);
            if (directoryListString != null) {
                try {
                    String[] directoryList = directoryListString.split(",");
                    loadDirectories(directoryList);
                } catch (FileStoreException e) {
                    throw new CertificateException(e);
                }
            }
            try {
                String proxyFilename =
                        properties.getProperty(PROXY_FILENAME);
                if (proxyFilename != null) {
                    loadProxyCertificate(proxyFilename);
                }
                String certFilename = properties.getProperty(CERTIFICATE_FILENAME);
                String keyFilename = properties.getProperty(KEY_FILENAME);
                if ((certFilename != null) &&
                        (keyFilename != null)) {
                    loadCertificateKey(certFilename, keyFilename);
                }
            } catch (FileStoreException e) {
                throw new CertificateException(e);
            } catch (CredentialException e) {
                e.printStackTrace();
                throw new CertificateException(e);
            }
        } finally {
            try {
                inputStream.close();
            } catch (IOException e) {
                logger.info("Error closing inputStream", e);
            }
        }
    }

    private void loadProxyCertificate(String proxyFilename) throws FileStoreException {

<<<<<<< HEAD
        if (proxyFilename == null) {
            return;
        }

<<<<<<< HEAD
        FileBasedProxyCredential credential = new FileBasedProxyCredential(new File(proxyFilename));
        this.aliasObjectMap.put(proxyFilename, credential);
=======
        proxyDelegate.loadWrappers(new String[]{proxyFilename});
        Map<String, FileBasedProxyCredential> wrapperMap =
                proxyDelegate.getWrapperMap();
        for (FileBasedProxyCredential credential : wrapperMap.values()) {
            this.aliasObjectMap.put(proxyFilename, credential);
        }
>>>>>>> a64ce28... filebasedobject rework take1
    }


    private void loadCertificateKey(String userCertFilename, String userKeyFilename)
            throws CredentialException {

        if ((userCertFilename == null) ||
                (userKeyFilename == null)) {
            return;
        }
<<<<<<< HEAD

        // Relative to what?
        File certFile = new File(userCertFilename);
        File keyFile = new File(userKeyFilename);
        FileBasedCertKeyCredential credential = new FileBasedCertKeyCredential(certFile, keyFile);
        // What do we name this alias?
        String alias = certFile.getName() + ":" + keyFile.getName();
        this.aliasObjectMap.put(alias, credential);

=======
        proxyDelegate.loadWrappers(new String[]{proxyFilename});
        Map<String, FileBasedProxyCredential> wrapperMap =
                proxyDelegate.getWrapperMap();
        for (FileBasedProxyCredential credential : wrapperMap.values()) {
            this.aliasObjectMap.put(proxyFilename, credential);
        }
    }


    private void loadCertificateKey(String userCertFilename, String userKeyFilename,
                                    KeyStore.ProtectionParameter protectionParameter) {
        //TODO: implement me.
>>>>>>> 1cd74b7... Rework X509Credential class to support clear or encrypted private key, and cert/file from separate streams.
=======
        // FIXME: Here the credential needs to be loaded and added to the Map.
>>>>>>> a64ce28... filebasedobject rework take1
    }


    private void loadDirectories(String[] directoryList)
            throws FileStoreException {

        caDelegate.loadWrappers(directoryList);
        Map<String, FileBasedTrustAnchor> wrapperMap = caDelegate.getWrapperMap();
        for (FileBasedTrustAnchor trustAnchor : wrapperMap
                .values()) {
            String alias = trustAnchor.getFile().getName();
<<<<<<< HEAD
=======
            certFilenameMap
                    .put(trustAnchor.getTrustAnchor().getTrustedCert(),
                            alias);
>>>>>>> a64ce28... filebasedobject rework take1
            this.aliasObjectMap.put(alias, trustAnchor);
        }
    }

    @Override
    public void engineDeleteEntry(String s) throws KeyStoreException {

        SingleFileBasedObject object = this.aliasObjectMap.remove(s);
        if (object != null) {
            if (object instanceof FileBasedTrustAnchor) {

                FileBasedTrustAnchor descriptor = (FileBasedTrustAnchor) object;
<<<<<<< HEAD
=======
                Certificate cert;
                try {
                    cert = descriptor.getTrustAnchor().getTrustedCert();
                } catch (FileStoreException e) {
                    throw new KeyStoreException(e);
                }
                this.certFilenameMap.remove(cert);
>>>>>>> a64ce28... filebasedobject rework take1
                boolean success = descriptor.getFile().delete();
                if (!success) {
                    // FIXME: warn? throw error?
                    logger.info("Unable to delete certificate");
                }
<<<<<<< HEAD
            } else if (object instanceof FileBasedCredential) {

                FileBasedCredential proxy = (FileBasedCredential) object;
                if (proxy instanceof SingleFileBasedObject) {
                    File file = ((SingleFileBasedObject) proxy).getFile();
                    boolean success = file.delete();
                    if (!success) {
                        // FIXME: warn? throw error?
                        logger.info("Unable to delete credential");
                    }
                } else if (proxy instanceof MultipleFileBasedObject) {
                    File certFile = ((MultipleFileBasedObject) proxy).getCertificateFile();
                    boolean success = certFile.delete();
                    if (!success) {
                        // FIXME: warn? throw error?
                        logger.info("Unable to delete credential");
                    }
                    File keyFile = ((MultipleFileBasedObject) proxy).getKeyFile();
                    success = keyFile.delete();
                    if (!success) {
                        // FIXME: warn? throw error?
                        logger.info("Unable to delete credential");
                    }
=======
            } else if (object instanceof FileBasedProxyCredential) {

                FileBasedProxyCredential proxy = (FileBasedProxyCredential) object;
                X509Credential credential;
                try {
                    credential = proxy.getCredential();
                } catch (FileStoreException e) {
                    throw new KeyStoreException(e);
                }
                this.proxyFilenameMap.remove(credential);
                boolean success = proxy.getFile().delete();
                if (!success) {
                    // FIXME: warn? throw error?
                    logger.info("Unable to delete credential");
>>>>>>> a64ce28... filebasedobject rework take1
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
        X509Credential credential = new X509Credential((PrivateKey) key, (X509Certificate[]) certificates);
        try {
<<<<<<< HEAD
            FileBasedCredential entry = getKeyEntry(s);
            if (entry != null) {
                if (entry instanceof FileBasedProxyCredential) {
                    FileBasedProxyCredential proxy = (FileBasedProxyCredential) entry;
                    File file = proxy.getFile();
                    credential.writeToFile(file);
                    proxy = new FileBasedProxyCredential(file, credential);
                    this.aliasObjectMap.put(s, proxy);
                } else if (entry instanceof FileBasedCertKeyCredential) {
                    FileBasedCertKeyCredential certKey = (FileBasedCertKeyCredential) entry;
                    File certFile = certKey.getCertificateFile();
                    File keyFile = certKey.getKeyFile();
                    credential.writeToFile(certFile, keyFile);
                    certKey = new FileBasedCertKeyCredential(certFile, keyFile, credential);
                    this.aliasObjectMap.put(s, certKey);
                }
            } else {
                if (credential.isEncryptedKey()) {
                    // FIXME: relative to what?
                    File certFile = new File(s + "-cert.pem");
                    File keyFile = new File(s + "-key.pem");
                    credential.writeToFile(certFile, keyFile);
                    FileBasedCertKeyCredential fileCertKey =
                            new FileBasedCertKeyCredential(certFile, keyFile, credential);
                    this.aliasObjectMap.put(s, fileCertKey);
                } else {
                    File file = new File(s + "-certkey.pem");
                    credential.writeToFile(file);
                    FileBasedProxyCredential fileProxy = new FileBasedProxyCredential(file, credential);
                    this.aliasObjectMap.put(s, fileProxy);
                }
            }
=======
            credential.writeToFile(file);
            FileBasedProxyCredential fileCred = new FileBasedProxyCredential(file.getName(), credential);
            this.aliasObjectMap.put(s, fileCred);
            this.proxyFilenameMap.put(credential, s);
>>>>>>> a64ce28... filebasedobject rework take1
        } catch (FileStoreException e) {
            throw new KeyStoreException("Error storing credential", e);
        } catch (IOException e) {
            throw new KeyStoreException("Error storing credential", e);
        } catch (CertificateEncodingException e) {
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
        FileBasedTrustAnchor trustAnchor = getCertificateEntry(alias);
        if (trustAnchor != null) {
            file = trustAnchor.getFile();
        } else {
            file = new File(alias);
        }
        X509Certificate x509Cert = (X509Certificate) certificate;
        try {
            writeCertificate(x509Cert, file);
            FileBasedTrustAnchor anchor = new FileBasedTrustAnchor(file, new TrustAnchor(x509Cert, null));
            this.aliasObjectMap.put(alias, anchor);
<<<<<<< HEAD
=======
            this.certFilenameMap.put(x509Cert, alias);
>>>>>>> a64ce28... filebasedobject rework take1
        } catch (FileStoreException e) {
            throw new KeyStoreException(e);
        } catch (IOException e) {
            throw new KeyStoreException(e);
        } catch (CertificateEncodingException e) {
            throw new KeyStoreException(e);
        }
    }
}
