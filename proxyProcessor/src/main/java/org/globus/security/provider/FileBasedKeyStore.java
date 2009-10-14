package org.globus.security.provider;

import org.globus.security.filestore.FileBasedKeyStoreParameters;
import org.globus.security.filestore.FileBasedStore;
import static org.globus.security.filestore.FileBasedStore.LoadFileType;
import org.globus.security.filestore.FileBasedTrustAnchor;
import org.globus.security.filestore.TrustAnchorWrapper;
import static org.globus.security.util.CertificateIOUtil.writeCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;


/**
 * This class is designed to act as a keystore based on multiple certificate
 * directories.
 */
public class FileBasedKeyStore extends KeyStoreSpi {

    private static Logger logger =
        LoggerFactory.getLogger(FileBasedCertStore.class.getName());
    public static final String DEFAULT_DIRECTORY_KEY = "default_directory";
    public static final String DIRECTORY_LIST_KEY = "directory_list";

    private Map<String, FileBasedTrustAnchor> certsAliasMap =
        new HashMap<String, FileBasedTrustAnchor>();
    private Map<Certificate, String> reverseAliasMap =
        new HashMap<Certificate, String>();
    private File defaultDirectory;

    private FileBasedStore delegate =
        FileBasedStore.getFileBasedStore(LoadFileType.CA_FILE);


    @Override
    public Key engineGetKey(String s, char[] chars)
        throws NoSuchAlgorithmException, UnrecoverableKeyException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean engineIsKeyEntry(String s) {
        return false;  //Always return false.  This is not used to store keys. . . yet
    }

    @Override
    public void engineStore(OutputStream outputStream, char[] chars) throws
                                                                     IOException,
                                                                     NoSuchAlgorithmException,
                                                                     CertificateException {
        for (TrustAnchorWrapper desc : this.certsAliasMap.values()) {
            File file = desc.getFile();
            if (file == null) {
                File outputFile =
                    new File(this.defaultDirectory, desc.getAlias() + ".0");
                desc.setFile(outputFile);
            }
            try {
                writeCertificate(desc.getTrustAnchor().getTrustedCert(),
                                 desc.getFile());
            } catch (CertStoreException e) {
                throw new CertificateException(e);
            }
        }
    }

    @Override
    public Date engineGetCreationDate(String s) {
        try {
            return this.certsAliasMap.get(s).getTrustAnchor().
                getTrustedCert().getNotBefore();
        } catch (CertStoreException e) {
            return new Date();
        }
    }

    @Override
    public String engineGetCertificateAlias(Certificate certificate) {
        return this.reverseAliasMap.get(certificate);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String s) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Certificate engineGetCertificate(String s) {
        try {
            FileBasedTrustAnchor trustAnchor = this.certsAliasMap.get(s);
            trustAnchor.refresh();
            return trustAnchor.getTrustAnchor().getTrustedCert();
        } catch (CertStoreException e) {
            return null;
        }
    }

    @Override
    public void engineLoad(KeyStore.LoadStoreParameter loadStoreParameter) throws IOException, NoSuchAlgorithmException, CertificateException {
        if(!(loadStoreParameter instanceof FileBasedKeyStoreParameters)){
            throw new IllegalArgumentException("Unable to process parameters: " +loadStoreParameter);
        }
        FileBasedKeyStoreParameters params = (FileBasedKeyStoreParameters) loadStoreParameter;
        try {
            loadDirectories(params.getCertDirs());
            loadDirectories(new String[]{params.getDefaultCertDir()});
        } catch (CertStoreException e) {
            throw new CertificateException(e);
        }
    }

    @Override
    public void engineLoad(InputStream inputStream, char[] chars)
        throws IOException, NoSuchAlgorithmException, CertificateException {
        try {
            Properties properties = new Properties();
            properties.load(inputStream);
            String defaultDirectoryString =
                properties.get(DEFAULT_DIRECTORY_KEY).toString();
            if (defaultDirectoryString != null) {
                defaultDirectory = new File(defaultDirectoryString);
                if (!defaultDirectory.exists()) {
                    boolean directoryMade = defaultDirectory.mkdirs();
                    if (!directoryMade) {
                        throw new IOException(
                            "Unable to create default certificate directory");
                    }
                }
            }
            String directoryListString =
                properties.getProperty(DIRECTORY_LIST_KEY);
            try {
                String[] directoryList =directoryListString.split(",");
                loadDirectories(directoryList);
                loadDirectories(new String[]{defaultDirectoryString});
            } catch (CertStoreException e) {
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

    private void loadDirectories(String[] directoryList) throws CertStoreException {
        delegate.loadWrappers(directoryList);
        delegate.getWrapperMap();
        for (FileBasedTrustAnchor trustAnchor : certsAliasMap
            .values()) {
            reverseAliasMap
                .put(trustAnchor.getTrustAnchor().getTrustedCert(),
                     trustAnchor.getAlias());
            this.certsAliasMap.put(trustAnchor.getAlias(), trustAnchor);
        }
    }

    @Override
    public void engineDeleteEntry(String s) throws KeyStoreException {
        FileBasedTrustAnchor descriptor = this.certsAliasMap.remove(s);
        Certificate cert;
        try {
            cert = descriptor.getTrustAnchor().getTrustedCert();
        } catch (CertStoreException e) {
            throw new KeyStoreException(e);
        }
        this.reverseAliasMap.remove(cert);
        boolean success = descriptor.getFile().delete();
        if (!success) {
            logger.info("Unable to delete certificate");
        }
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(this.certsAliasMap.keySet());

    }

    @Override
    public void engineSetKeyEntry(String s, Key key, char[] chars,
                                  Certificate[] certificates)
        throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void engineSetKeyEntry(String s, byte[] bytes,
                                  Certificate[] certificates)
        throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean engineContainsAlias(String s) {
        return this.certsAliasMap.containsKey(s);
    }

    @Override
    public int engineSize() {
        return this.certsAliasMap.size();
    }

    @Override
    public boolean engineIsCertificateEntry(String s) {
        return this.certsAliasMap.containsKey(s);
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate certificate)
        throws KeyStoreException {
        FileBasedTrustAnchor descriptor;
        try {
            descriptor = new FileBasedTrustAnchor(alias,
                                                  new TrustAnchor(
                                                      (X509Certificate)certificate,
                                                      null));
            this.certsAliasMap.put(alias, descriptor);
            this.reverseAliasMap.put(descriptor.getTrustAnchor().
                getTrustedCert(), alias);
        } catch (CertStoreException e) {
            throw new KeyStoreException(e);
        }

    }

}
