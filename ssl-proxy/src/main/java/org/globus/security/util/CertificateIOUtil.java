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

package org.globus.security.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * Fill Me
 */
public final class CertificateIOUtil {

    // for PEM strings
    public static final int LINE_LENGTH = 64;
    public static final String LINE_SEP = "\n";
    public static final String CERT_HEADER = "-----BEGIN CERTIFICATE-----";
    public static final String CERT_FOOTER = "-----END CERTIFICATE-----";
    public static final String KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    public static final String KEY_FOOTER = "-----END RSA PRIVATE KEY-----";

    private static Logger logger = Logger.getLogger(CertificateIOUtil.class.getCanonicalName());
    private static Base64 base64 = new Base64();
    private static MessageDigest md5;

    private CertificateIOUtil() {
        //This should not be instantiated
    }

    private static void init() {
        if (md5 == null) {
            try {
                md5 = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException e) {
                logger.log(Level.SEVERE, "", e);
            }
        }
    }


    /**
     * Returns equivalent of:
     * openssl x509 -in "cert-file" -hash -noout
     *
     * @param subjectDN
     * @return hash for certificate names
     */
    public static String nameHash(Principal subjectDN) {
        try {
            return hash(encodePrincipal(subjectDN));
        } catch (Exception e) {
            logger.log(Level.SEVERE, "", e);
            return null;
        }
    }

    public static byte[] encodePrincipal(Principal subject) throws IOException {
        if (subject instanceof X500Principal) {
            return ((X500Principal) subject).getEncoded();
            //} else if (subject instanceof X500Name) {
            //    return ((X500Name)subject).getEncoded();
        } else if (subject instanceof X509Name) {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            DEROutputStream der = new DEROutputStream(bout);
            X509Name nm = (X509Name) subject;
            der.writeObject(nm.getDERObject());
            return bout.toByteArray();
        } else {
            throw new ClassCastException("unsupported input class: "
                    + subject.getClass().toString());
        }
    }

    private static String hash(byte[] data) {
        init();
        if (md5 == null) {
            return null;
        }

        md5.reset();
        md5.update(data);

        byte[] md = md5.digest();

        long ret = (fixByte(md[0]) | (fixByte(md[1]) << 8L));
        ret = ret | fixByte(md[2]) << 16L;
        ret = ret | fixByte(md[3]) << 24L;
        ret = ret & 0xffffffffL;

        return Long.toHexString(ret);
    }

    private static long fixByte(byte b) {
        return (b < 0) ? (long) (b + 256) : (long) b;
    }

    public static void writeCertificate(X509Certificate cert, File path)
            throws CertificateEncodingException, IOException {
        String pubKeyPEM = certToPEMString(base64.encodeToString(cert.getEncoded()));
        FileWriter pubFile = null;
        try {
            pubFile = new FileWriter(path);
            pubFile.write(pubKeyPEM);
        } finally {
            if (pubFile != null) {
                pubFile.close();
            }
        }
    }

    /**
     * Creates PEM encoded cert string with line length, header and footer.
     *
     * @param base64Data already encoded into string
     * @return string
     */
    public static String certToPEMString(String base64Data) {
        return toStringImpl(base64Data, false);
    }

    /**
     * Writes certificate to the specified output stream in PEM format.
     */
    public static void writeCertificate(
            OutputStream out,
            X509Certificate cert)
            throws IOException, CertificateEncodingException {
        PEMUtil.writeBase64(out,
                "-----BEGIN CERTIFICATE-----",
                base64.encode(cert.getEncoded()),
                "-----END CERTIFICATE-----");
    }


    private static String toStringImpl(String base64Data, boolean isKey) {

        int length = LINE_LENGTH;
        int offset = 0;

        final StringBuffer buf = new StringBuffer(2048);

        if (isKey) {
            buf.append(KEY_HEADER);
        } else {
            buf.append(CERT_HEADER);
        }
        buf.append(LINE_SEP);

        final int size = base64Data.length();
        while (offset < size) {
            if (LINE_LENGTH > (size - offset)) {
                length = size - offset;
            }
            buf.append(base64Data.substring(offset, offset + length));
            buf.append(LINE_SEP);
            offset = offset + LINE_LENGTH;
        }

        if (isKey) {
            buf.append(KEY_FOOTER);
        } else {
            buf.append(CERT_FOOTER);
        }
        buf.append(LINE_SEP);

        return buf.toString();
    }
}

