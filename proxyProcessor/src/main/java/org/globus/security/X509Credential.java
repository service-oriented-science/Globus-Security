/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.security;

import org.bouncycastle.util.encoders.Base64;
import org.globus.security.bc.BouncyCastleOpenSSLKey;
import org.globus.security.filestore.FileBasedSigningPolicyStore;
import org.globus.security.util.CertificateLoadUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Vector;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class X509Credential {

    private static Logger logger =
        LoggerFactory.getLogger(FileBasedSigningPolicyStore.class.getName());

    private PrivateKey key;
    private X509Certificate[] certChain;

    public X509Credential(PrivateKey key_, X509Certificate[] certChain_) {

        if (key_ == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        if ((certChain_ == null) ||
            (certChain_.length < 1)) {
            throw new IllegalArgumentException(
                "Atleast one public certificate required");
        }

        this.certChain = certChain_;
        this.key = key_;
    }

    public X509Credential(InputStream stream) throws CredentialException {
        loadCredential(stream);
    }

    protected void loadCredential(InputStream input)
        throws CredentialException {

        if (input == null) {
            throw new IllegalArgumentException(
                "Inputstream to load X509Credential is null");
        }

        PrivateKey key = null;
        X509Certificate cert = null;
        Vector chain = new Vector();

        String line;
        BufferedReader reader = null;

        try {
            reader = new BufferedReader(new InputStreamReader(input));

            while ((line = reader.readLine()) != null) {

                if (line.indexOf("BEGIN CERTIFICATE") != -1) {
                    byte[] data = getDecodedPEMObject(reader);
                    cert = CertificateLoadUtil
                        .loadCertificate(new ByteArrayInputStream(data));
                    chain.addElement(cert);
                } else if (line.indexOf("BEGIN RSA PRIVATE KEY") != -1) {
                    byte[] data = getDecodedPEMObject(reader);
                    // FIXME: BC seems to have some PEM utility but the actual
                    // load is in private methods and cannot be leveraged.
                    // Investigate availability of standard libraries for these
                    // low level reads. FOr now, copying from CoG
                    OpenSSLKey k = new BouncyCastleOpenSSLKey("RSA", data);
                    key = k.getPrivateKey();
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
                }
            }
        }

        int size = chain.size();

        if (size == 0) {
            throw new CredentialException("No certificates found.");
        }

        if (key == null) {
            throw new CredentialException("NO private key found");
        }

        // set chain
        this.certChain = new X509Certificate[size];
        chain.copyInto(this.certChain);

        // set key
        this.key = key;
    }

    /**
     * Reads Base64 encoded data from the stream and returns its decoded value.
     * The reading continues until the "END" string is found in the data.
     * Otherwise, returns null.
     */
    private static final byte[] getDecodedPEMObject(BufferedReader reader)
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


}
