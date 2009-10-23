package org.globus.security.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;

import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x509.X509Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateIOUtil {

    static Logger logger = LoggerFactory.getLogger(CertificateIOUtil.class.getName());
    private static Base64 base64 = new Base64();


    // for PEM strings
    public static final int LINE_LENGTH = 64;
    public static final String lineSep = "\n";
    public static final String certHeader = "-----BEGIN CERTIFICATE-----";
    public static final String certFooter = "-----END CERTIFICATE-----";
    public static final String keyHeader = "-----BEGIN RSA PRIVATE KEY-----";
    public static final String keyFooter = "-----END RSA PRIVATE KEY-----";


    private static MessageDigest md5 = null;

    private static void init() {
        if (md5 == null) {
            try {
                md5 = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException e) {
                logger.error("", e);
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
            logger.error("", e);
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
        if (md5 == null) return null;

        md5.reset();
        md5.update(data);

        byte[] md = md5.digest();

        long ret = (fixByte(md[0]) | (fixByte(md[1]) << 8L) |
                fixByte(md[2]) << 16L | fixByte(md[3]) << 24L) & 0xffffffffL;

        return Long.toHexString(ret);
    }

    private static long fixByte(byte b) {
        return (b < 0) ? (long) (b + 256) : (long) b;
    }

    public static void writeCertificate(X509Certificate cert, File path) throws CertificateEncodingException, IOException {
        final String pubKeyPEM =
                certToPEMString(base64.encodeToString(cert.getEncoded()));
        final FileWriter pubFile = new FileWriter(path);
        pubFile.write(pubKeyPEM);
        pubFile.close();
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

    private static String toStringImpl(String base64Data, boolean isKey) {

        int length = LINE_LENGTH;
        int offset = 0;

        final StringBuffer buf = new StringBuffer(2048);

        if (isKey) {
            buf.append(keyHeader);
        } else {
            buf.append(certHeader);
        }
        buf.append(lineSep);

        final int size = base64Data.length();
        while (offset < size) {
            if (LINE_LENGTH > (size - offset)) {
                length = size - offset;
            }
            buf.append(base64Data.substring(offset, offset + length));
            buf.append(lineSep);
            offset = offset + LINE_LENGTH;
        }

        if (isKey) {
            buf.append(keyFooter);
        } else {
            buf.append(certFooter);
        }
        buf.append(lineSep);

        return buf.toString();
    }
}

