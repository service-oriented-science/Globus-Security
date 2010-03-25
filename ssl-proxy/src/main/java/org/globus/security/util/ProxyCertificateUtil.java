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

import java.io.IOException;

import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.globus.security.Constants;
import org.globus.security.proxyExtension.ProxyCertInfo;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public final class ProxyCertificateUtil {

    private ProxyCertificateUtil() {
        //This should not be instantiated
    }

    /**
     * Determines if a specified certificate type indicates a GSI-2, GSI-3 or
     * GSI-4proxy certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-2 or GSI-3 or GSI-4 proxy, false
     *         otherwise.
     */
    public static boolean isProxy(Constants.CertificateType certType) {
        return isGsi2Proxy(certType) || isGsi3Proxy(certType) || isGsi4Proxy(certType);
    }

    /**
     * Determines if a specified certificate type indicates a GSI-4 proxy
     * certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-4 proxy, false otherwise.
     */
    public static boolean isGsi4Proxy(Constants.CertificateType certType) {
        return certType == Constants.CertificateType.GSI_4_IMPERSONATION_PROXY
                || certType == Constants.CertificateType.GSI_4_INDEPENDENT_PROXY
                || certType == Constants.CertificateType.GSI_4_RESTRICTED_PROXY
                || certType == Constants.CertificateType.GSI_4_LIMITED_PROXY;
    }

    /**
     * Determines if a specified certificate type indicates a GSI-3 proxy
     * certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-3 proxy, false otherwise.
     */
    public static boolean isGsi3Proxy(Constants.CertificateType certType) {
        return certType == Constants.CertificateType.GSI_3_IMPERSONATION_PROXY
                || certType == Constants.CertificateType.GSI_3_INDEPENDENT_PROXY
                || certType == Constants.CertificateType.GSI_3_RESTRICTED_PROXY
                || certType == Constants.CertificateType.GSI_3_LIMITED_PROXY;
    }

    /**
     * Determines if a specified certificate type indicates a GSI-2 proxy
     * certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-2 proxy, false otherwise.
     */
    public static boolean isGsi2Proxy(Constants.CertificateType certType) {
        return certType == Constants.CertificateType.GSI_2_PROXY
                || certType == Constants.CertificateType.GSI_2_LIMITED_PROXY;
    }

    /**
     * Determines if a specified certificate type indicates a GSI-2 or GSI-3 or
     * GSI=4 limited proxy certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-2 or GSI-3 or GSI-4 limited proxy,
     *         false otherwise.
     */
    public static boolean isLimitedProxy(Constants.CertificateType certType) {
        return certType == Constants.CertificateType.GSI_3_LIMITED_PROXY
                || certType == Constants.CertificateType.GSI_2_LIMITED_PROXY
                || certType == Constants.CertificateType.GSI_4_LIMITED_PROXY;
    }

    /**
     * Determines if a specified certificate type indicates a GSI-3 or GS-4
     * limited proxy certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-3 or GSI-4 independent proxy, false
     *         otherwise.
     */
    public static boolean isIndependentProxy(
            Constants.CertificateType certType) {
        return certType == Constants.CertificateType.GSI_3_INDEPENDENT_PROXY
                || certType == Constants.CertificateType.GSI_4_INDEPENDENT_PROXY;
    }

    /**
     * Determines if a specified certificate type indicates a GSI-2 or GSI-3 or
     * GSI-4 impersonation proxy certificate.
     *
     * @param certType the certificate type to check.
     * @return true if certType is a GSI-2 or GSI-3 or GSI-4 impersonation
     *         proxy, false otherwise.
     */
    public static boolean isImpersonationProxy(Constants.CertificateType certType) {
        return certType == Constants.CertificateType.GSI_3_IMPERSONATION_PROXY
                || certType == Constants.CertificateType.GSI_3_LIMITED_PROXY
                || certType == Constants.CertificateType.GSI_4_IMPERSONATION_PROXY
                || certType == Constants.CertificateType.GSI_4_LIMITED_PROXY
                || certType == Constants.CertificateType.GSI_2_LIMITED_PROXY
                || certType == Constants.CertificateType.GSI_2_PROXY;

    }

    public static int getProxyPathConstraint(TBSCertificateStructure crt)
            throws IOException {

        ProxyCertInfo proxyCertExt = getProxyCertInfo(crt);
        return (proxyCertExt != null) ? proxyCertExt.getPathLenConstraint() : -1;
    }

    public static ProxyCertInfo getProxyCertInfo(TBSCertificateStructure crt)
            throws IOException {

        X509Extensions extensions = crt.getExtensions();
        if (extensions == null) {
            return null;
        }
        X509Extension ext =
                extensions.getExtension(Constants.PROXY_OID);
        if (ext == null) {
            ext = extensions.getExtension(Constants.PROXY_OLD_OID);
        }
        return (ext != null) ? getProxyCertInfo(ext) : null;
    }

    public static ProxyCertInfo getProxyCertInfo(X509Extension ext) {

        byte[] value = ext.getValue().getOctets();
        return ProxyCertInfo.getInstance(value);
    }


}