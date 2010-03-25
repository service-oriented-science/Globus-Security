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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.StringTokenizer;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.globus.security.Constants;
import org.globus.security.proxyExtension.ProxyCertInfo;
import org.globus.security.proxyExtension.ProxyPolicy;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public final class CertificateUtil {

    public static final int DIGITAL_SIGNATURE = 0;
    public static final int NON_REPUDIATION = 1;
    public static final int KEY_ENCIPHERMENT = 2;
    public static final int DATA_ENCIPHERMENT = 3;
    public static final int KEY_AGREEMENT = 4;
    public static final int KEY_CERTSIGN = 5;
    public static final int CRL_SIGN = 6;
    public static final int ENCIPHER_ONLY = 7;
    public static final int DECIPHER_ONLY = 8;
    public static final int DEFAULT_USAGE_LENGTH = 9;

    private CertificateUtil() {
        //this should not be constructed;
    }

    /**
     * Return CA Path constraint
     *
     * @param crt
     * @return
     * @throws IOException
     */
    public static int getCAPathConstraint(TBSCertificateStructure crt)
            throws IOException {

        X509Extensions extensions = crt.getExtensions();
        if (extensions == null) {
            return -1;
        }
        X509Extension proxyExtension =
                extensions.getExtension(X509Extensions.BasicConstraints);
        if (proxyExtension != null) {
            BasicConstraints basicExt =
                    getBasicConstraints(proxyExtension);
            if (basicExt.isCA()) {
                BigInteger pathLen = basicExt.getPathLenConstraint();
                return (pathLen == null) ? Integer.MAX_VALUE : pathLen.intValue();
            } else {
                return -1;
            }
        }
        return -1;
    }

    /**
     * Returns certificate type of the given TBS certificate. <BR> The
     * certificate type is {@link org.globus.security.Constants.CertificateType#CA
     * CertificateType.CA} <B>only</B> if the certificate contains a
     * BasicConstraints extension and it is marked as CA.<BR> A certificate is a
     * GSI-2 proxy when the subject DN of the certificate ends with
     * <I>"CN=proxy"</I> (certificate type {@link org.globus.security.Constants.CertificateType#GSI_2_PROXY
     * CertificateType.GSI_2_PROXY}) or <I>"CN=limited proxy"</I> (certificate
     * type {@link org.globus.security.Constants.CertificateType#GSI_2_LIMITED_PROXY
     * CertificateType.LIMITED_PROXY}) component and the issuer DN of the
     * certificate matches the subject DN without the last proxy <I>CN</I>
     * component.<BR> A certificate is a GSI-3 proxy when the subject DN of the
     * certificate ends with a <I>CN</I> component, the issuer DN of the
     * certificate matches the subject DN without the last <I>CN</I> component
     * and the certificate contains {@link org.globus.security.proxyExtension.ProxyCertInfo
     * ProxyCertInfo} critical extension. The certificate type is {@link
     * org.globus.security.Constants.CertificateType#GSI_3_IMPERSONATION_PROXY
     * CertificateType.GSI_3_IMPERSONATION_PROXY} if the policy language of the
     * {@link org.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo}
     * extension is set to {@link org.globus.security.proxyExtension.ProxyPolicy#IMPERSONATION
     * ProxyPolicy.IMPERSONATION} OID. The certificate type is {@link
     * org.globus.security.Constants.CertificateType#GSI_3_LIMITED_PROXY
     * CertificateType.GSI_3_LIMITED_PROXY} if the policy language of the {@link
     * org.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo} extension
     * is set to {@link org.globus.security.proxyExtension.ProxyPolicy#LIMITED
     * ProxyPolicy.LIMITED} OID. The certificate type is {@link
     * org.globus.security.Constants.CertificateType#GSI_3_INDEPENDENT_PROXY
     * CertificateType.GSI_3_INDEPENDENT_PROXY} if the policy language of the
     * {@link org.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo}
     * extension is set to {@link org.globus.security.proxyExtension.ProxyPolicy#INDEPENDENT
     * ProxyPolicy.INDEPENDENT} OID. The certificate type is {@link
     * org.globus.security.Constants.CertificateType#GSI_3_RESTRICTED_PROXY
     * CertificateType.GSI_3_RESTRICTED_PROXY} if the policy language of the
     * {@link org.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo}
     * extension is set to any other OID then the above.<BR> The certificate
     * type is {@link org.globus.security.Constants.CertificateType#EEC
     * CertificateType.EEC} if the certificate is not a CA certificate or a
     * GSI-2 or GSI-3 proxy.
     *
     * @param crt the TBS certificate to get the type of.
     * @return the certificate type. The certificate type is determined by rules
     *         described above.
     * @throws java.io.IOException if something goes wrong.
     * @throws java.security.cert.CertificateException
     *                             for proxy certificates, if the issuer DN of
     *                             the certificate does not match the subject DN
     *                             of the certificate without the last <I>CN</I>
     *                             component. Also, for GSI-3 proxies when the
     *                             <code>ProxyCertInfo</code> extension is not
     *                             marked as critical.
     */
    public static Constants.CertificateType getCertificateType(
            TBSCertificateStructure crt)
            throws CertificateException, IOException {

        X509Extensions extensions = crt.getExtensions();
        X509Extension ext = null;

        if (extensions != null) {
            ext = extensions.getExtension(X509Extensions.BasicConstraints);
            if (ext != null) {
                BasicConstraints basicExt = getBasicConstraints(ext);
                if (basicExt.isCA()) {
                    return Constants.CertificateType.CA;
                }
            }
        }

        Constants.CertificateType type = Constants.CertificateType.EEC;

        // does not handle multiple AVAs
        X509Name subject = crt.getSubject();

        ASN1Set entry = X509NameHelper.getLastNameEntry(subject);
        ASN1Sequence ava = (ASN1Sequence) entry.getObjectAt(0);
        if (X509Name.CN.equals(ava.getObjectAt(0))) {
            type = processCN(extensions, type, ava);
        }

        return type;
    }

    private static Constants.CertificateType processCN(
            X509Extensions extensions, Constants.CertificateType type, ASN1Sequence ava) throws CertificateException {
        X509Extension ext;
        String value = ((DERString) ava.getObjectAt(1)).getString();
        Constants.CertificateType certType = type;
        if (value.equalsIgnoreCase("proxy")) {
            certType = Constants.CertificateType.GSI_2_PROXY;
        } else if (value.equalsIgnoreCase("limited proxy")) {
            certType = Constants.CertificateType.GSI_2_LIMITED_PROXY;
        } else if (extensions != null) {
            boolean gsi4 = true;
            // GSI_4
            ext = extensions.getExtension(Constants.PROXY_OID);
            if (ext == null) {
                // GSI_3
                ext = extensions.getExtension(Constants.PROXY_OLD_OID);
                gsi4 = false;
            }
            if (ext != null) {
                if (ext.isCritical()) {
                    certType = processCriticalExtension(ext, gsi4);
                } else {
                    String err = "proxyCertCritical";
                    throw new CertificateException(err);
                }
            }
        }

        /** FIXME: this looks like validation
         if (ProxyCertificateUtil.isProxy(type)) {
         X509NameHelper iss = new X509NameHelper(crt.getIssuer());
         iss.add((ASN1Set)BouncyCastleUtil.duplicate(entry));
         X509Name issuer = iss.getAsName();
         if (!issuer.equals(subject)) {
         String err = i18n.getMessage("proxyDNErr");
         throw new CertificateException(err);
         }
         }
         */
        return certType;
    }

    private static Constants.CertificateType processCriticalExtension(X509Extension ext, boolean gsi4) {
        Constants.CertificateType type;
        ProxyCertInfo proxyCertExt =
                ProxyCertificateUtil.getProxyCertInfo(ext);
        ProxyPolicy proxyPolicy =
                proxyCertExt.getProxyPolicy();
        DERObjectIdentifier oid =
                proxyPolicy.getPolicyLanguage();
        if (ProxyPolicy.IMPERSONATION.equals(oid)) {
            if (gsi4) {
                type =
                        Constants.CertificateType.GSI_4_IMPERSONATION_PROXY;
            } else {
                type =
                        Constants.CertificateType.GSI_3_IMPERSONATION_PROXY;
            }
        } else if (ProxyPolicy.INDEPENDENT.equals(oid)) {
            if (gsi4) {
                type =
                        Constants.CertificateType.GSI_4_INDEPENDENT_PROXY;
            } else {
                type =
                        Constants.CertificateType.GSI_3_INDEPENDENT_PROXY;
            }
        } else if (ProxyPolicy.LIMITED.equals(oid)) {
            if (gsi4) {
                type =
                        Constants.CertificateType.GSI_4_LIMITED_PROXY;
            } else {
                type =
                        Constants.CertificateType.GSI_3_LIMITED_PROXY;
            }
        } else {
            if (gsi4) {
                type =
                        Constants.CertificateType.GSI_4_RESTRICTED_PROXY;
            } else {
                type =
                        Constants.CertificateType.GSI_3_RESTRICTED_PROXY;
            }
        }
        return type;
    }

    /**
     * Creates a <code>BasicConstraints</code> object from given extension.
     *
     * @param ext the extension.
     * @return the <code>BasicConstraints</code> object.
     * @throws IOException if something fails.
     */
    public static BasicConstraints getBasicConstraints(X509Extension ext)
            throws IOException {

        ASN1Object object = X509Extension.convertValueToObject(ext);
        return BasicConstraints.getInstance(object);
    }


    /**
     * Converts the DER-encoded byte array into a <code>DERObject</code>.
     *
     * @param data the DER-encoded byte array to convert.
     * @return the DERObject.
     * @throws IOException if conversion fails
     */
    public static DERObject toDERObject(byte[] data)
            throws IOException {
        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        ASN1InputStream derInputStream = new ASN1InputStream(inStream);
        return derInputStream.readObject();
    }


    /**
     * Extracts the TBS certificate from the given certificate.
     *
     * @param cert the X.509 certificate to extract the TBS certificate from.
     * @return the TBS certificate
     * @throws IOException                  if extraction fails.
     * @throws CertificateEncodingException if extraction fails.
     */
    public static TBSCertificateStructure getTBSCertificateStructure(
            X509Certificate cert)
            throws CertificateEncodingException, IOException {
        DERObject obj = toDERObject(cert.getTBSCertificate());
        return TBSCertificateStructure.getInstance(obj);
    }

    public static boolean[] getKeyUsage(TBSCertificateStructure crt)
            throws IOException {
        X509Extensions extensions = crt.getExtensions();
        if (extensions == null) {
            return new boolean[0];
        }
        X509Extension extension =
                extensions.getExtension(X509Extensions.KeyUsage);
        return (extension != null) ? getKeyUsage(extension) : new boolean[0];
    }

    /**
     * Gets a boolean array representing bits of the KeyUsage extension.
     *
     * @throws IOException if failed to extract the KeyUsage extension value.
     * @see java.security.cert.X509Certificate#getKeyUsage
     */
    public static boolean[] getKeyUsage(X509Extension ext)
            throws IOException {
        DERBitString bits = (DERBitString) getExtensionObject(ext);

        // copied from X509CertificateObject
        byte[] bytes = bits.getBytes();
        int length = (bytes.length * 8) - bits.getPadBits();

        boolean[] keyUsage = new boolean[(length < DEFAULT_USAGE_LENGTH) ? DEFAULT_USAGE_LENGTH : length];

        for (int i = 0; i != length; i++) {
            keyUsage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
        }

        return keyUsage;
    }

    /**
     * Extracts the value of a certificate extension.
     *
     * @param ext the certificate extension to extract the value from.
     * @throws IOException if extraction fails.
     */
    public static DERObject getExtensionObject(X509Extension ext)
            throws IOException {
        return toDERObject(ext.getValue().getOctets());
    }

    /**
     * Converts DN of the form "CN=A, OU=B, O=C" into Globus format
     * "/O=C/OU=B/CN=A" <BR> This function might return incorrect
     * Globus-formatted ID when one of the RDNs in the DN contains commas.
     *
     * @return the converted DN in Globus format.
     */
    public static String toGlobusID(X500Principal principal) {

        if (principal == null) {
            return null;
        }

        String dn = principal.getName();

        StringTokenizer tokens = new StringTokenizer(dn, ",");
        StringBuffer buf = new StringBuffer();
        String token;

        while (tokens.hasMoreTokens()) {
            token = tokens.nextToken().trim();
            buf.insert(0, token);
            buf.insert(0, "/");
        }
        return buf.toString();
    }

    public static X500Principal toPrincipal(String globusID) {

        if (globusID == null) {
            return null;
        }
        String id = globusID.trim();
        StringTokenizer tokens = new StringTokenizer(id, "/");
        StringBuffer buf = new StringBuffer();
        String token;

        if (tokens.hasMoreTokens()) {
            token = tokens.nextToken().trim();
            buf.insert(0, token);
        }

        while (tokens.hasMoreTokens()) {
            token = tokens.nextToken().trim();

            buf.insert(0, ",");
            buf.insert(0, token);
        }

        String dn = buf.toString();

        return new X500Principal(dn);
    }


}
