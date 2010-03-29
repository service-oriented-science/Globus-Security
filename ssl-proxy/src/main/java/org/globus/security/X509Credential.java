/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
package org.globus.security;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.util.encoders.Base64;
import org.globus.security.bc.BouncyCastleOpenSSLKey;
import org.globus.security.util.CertificateIOUtil;
import org.globus.security.util.CertificateLoadUtil;

/**
 * FILL ME
 * <p/>
 * This class equivalent was called GlobusCredential in CoG -maybe a better name?
 *
 * @author ranantha@mcs.anl.gov
 */
public class X509Credential {

    public static final int BUFFER_SIZE = Integer.MAX_VALUE;

    private static Logger logger =
            Logger.getLogger(X509Credential.class.getCanonicalName());

    private OpenSSLKey opensslKey;
    private X509Certificate[] certChain;

    public X509Credential(PrivateKey initKey, X509Certificate[] initCertChain) {

        if (initKey == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        if ((initCertChain == null) || (initCertChain.length < 1)) {
            throw new IllegalArgumentException("Atleast one public certificate required");
        }

        this.certChain = new X509Certificate[initCertChain.length];
        System.arraycopy(initCertChain, 0, this.certChain, 0, initCertChain.length);
        this.opensslKey = new BouncyCastleOpenSSLKey(initKey);
    }


    public X509Credential(InputStream certInputStream, InputStream keyInputStream)
            throws CredentialException {
        if (certInputStream.markSupported()) {
            certInputStream.mark(BUFFER_SIZE);
        }
        loadKey(keyInputStream);
        loadCertificate(certInputStream);
        validateCredential();
    }

    public X509Certificate[] getCertificateChain() {
        X509Certificate[] returnArray = new X509Certificate[this.certChain.length];
        System.arraycopy(this.certChain, 0, returnArray, 0, this.certChain.length);
        return returnArray;
    }

    public Key getPrivateKey() throws CredentialException {

        return getPrivateKey(null);
    }

    public Key getPrivateKey(String password) throws CredentialException {

        if (this.opensslKey.isEncrypted()) {
            if (password == null) {
                throw new CredentialException("Key encrypted, password required");
            } else {
                try {
                    this.opensslKey.decrypt(password);
                } catch (GeneralSecurityException exp) {
                    throw new CredentialException(exp.getMessage(), exp);
                }
            }
        }
        return this.opensslKey.getPrivateKey();

    }

    public boolean isEncryptedKey() {
        return this.opensslKey.isEncrypted();
    }

    protected void loadCertificate(InputStream input)
            throws CredentialException {

        if (input == null) {
            throw new IllegalArgumentException(
                    "Input stream to load X509Credential is null");
        }

        X509Certificate cert;
        Vector<X509Certificate> chain = new Vector<X509Certificate>();

        String line;
        BufferedReader reader = null;
        try {
            if (input.markSupported()) {
                input.reset();
            }
            reader = new BufferedReader(new InputStreamReader(input));

            while ((line = reader.readLine()) != null) {

                if (line.indexOf("BEGIN CERTIFICATE") != -1) {
                    byte[] data = getDecodedPEMObject(reader);
                    cert = CertificateLoadUtil
                            .loadCertificate(new ByteArrayInputStream(data));
                    chain.addElement(cert);
                }
            }

        } catch (IOException e) {
            throw new CredentialException(e);
        } catch (GeneralSecurityException e) {
            throw new CredentialException(e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    logger.log(Level.FINE, "error closing reader", e);
                    //This is ok
                }
            }
        }

        int size = chain.size();
        if (size > 0) {
            // set chain
            this.certChain = new X509Certificate[size];
            chain.copyInto(this.certChain);
        }

    }

    protected void loadKey(InputStream input) throws CredentialException {

        // FIXME: BC seems to have some PEM utility but the actual
        // load is in private methods and cannot be leveraged.
        // Investigate availability of standard libraries for these
        // low level reads. FOr now, copying from CoG

        try {
            this.opensslKey = new BouncyCastleOpenSSLKey(input);
        } catch (IOException e) {
            throw new CredentialException(e.getMessage(), e);
        } catch (GeneralSecurityException e) {
            throw new CredentialException(e.getMessage(), e);
        }
    }

    private void validateCredential() throws CredentialException {

        if (this.certChain == null) {
            throw new CredentialException("No certificates found");
        }
        int size = this.certChain.length;

        if (size < 0) {
            throw new CredentialException("No certificates found.");
        }

        if (this.opensslKey == null) {
            throw new CredentialException("NO private key found");
        }
    }

    /**
     * Reads Base64 encoded data from the stream and returns its decoded value. The reading continues until the "END"
     * string is found in the data. Otherwise, returns null.
     */
    private static byte[] getDecodedPEMObject(BufferedReader reader)
            throws IOException {
        String line;
        StringBuffer buf = new StringBuffer();
        while ((line = reader.readLine()) != null) {
            if (line.indexOf("--END") != -1) { // found end
                return Base64.decode(buf.toString().getBytes());
            } else {
                buf.append(line);
            }
        }
        throw new EOFException("Missing PEM end footer");
    }

    public void saveKey(OutputStream out) throws IOException {

        this.opensslKey.writeTo(out);
        out.flush();
    }

    public void saveCertificateChain(OutputStream out)
            throws IOException, CertificateEncodingException {

        CertificateIOUtil.writeCertificate(out, this.certChain[0]);

        for (int i = 1; i < this.certChain.length; i++) {
            // FIXME: should we skip the self-signed certificates?
            if (this.certChain[i].getSubjectDN().equals(certChain[i].getIssuerDN())) {
                continue;
            }
            CertificateIOUtil.writeCertificate(out, this.certChain[i]);
        }

        out.flush();
    }

    public void save(OutputStream out) throws IOException, CertificateEncodingException {
        saveKey(out);
        saveCertificateChain(out);
    }

    public void writeToFile(File file) throws IOException, CertificateEncodingException {
        writeToFile(file, file);
    }

    public void writeToFile(File certFile, File keyFile) throws IOException, CertificateEncodingException {
        FileOutputStream keyOutputStream = null;
        FileOutputStream certOutputStream = null;
        try {
            keyOutputStream = new FileOutputStream(keyFile);
            certOutputStream = new FileOutputStream(certFile);
            saveKey(keyOutputStream);
            saveCertificateChain(certOutputStream);
        } finally {
            try {
                if (keyOutputStream != null) {
                    keyOutputStream.close();
                }
            } catch (IOException e) {
                logger.warning("Could not close stream on save of key to file. " + keyFile.getPath());
            }
            try {
                if (certOutputStream != null) {
                    certOutputStream.close();
                }
            } catch (IOException e) {
                logger.warning("Could not close stream on save certificate chain to file. " + certFile.getPath());
            }
        }
    }

    public Date getNotBefore() {
        Date notBefore = this.certChain[0].getNotBefore();
        for (int i = 1; i < this.certChain.length; i++) {
            Date date = this.certChain[i].getNotBefore();
            if (date.before(notBefore)) {
                notBefore = date;
            }
        }
        return notBefore;
    }

}
