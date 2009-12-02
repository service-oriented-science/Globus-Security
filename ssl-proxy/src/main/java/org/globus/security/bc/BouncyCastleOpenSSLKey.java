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
package org.globus.security.bc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;

import org.globus.security.OpenSSLKey;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * BouncyCastle-based implementation of OpenSSLKey.
 */
public class BouncyCastleOpenSSLKey extends OpenSSLKey {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public BouncyCastleOpenSSLKey(InputStream is)
            throws IOException, GeneralSecurityException {
        super(is);
    }

    public BouncyCastleOpenSSLKey(String file)
            throws IOException, GeneralSecurityException {
        super(file);
    }

    public BouncyCastleOpenSSLKey(PrivateKey key) {
        super(key);
    }

    public BouncyCastleOpenSSLKey(String algorithm, byte[] data)
            throws GeneralSecurityException {
        super(algorithm, data);
    }

    protected PrivateKey getKey(String alg, byte[] data)
            throws GeneralSecurityException {
        if (alg.equals("RSA")) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(data);
                ASN1InputStream derin = new ASN1InputStream(bis);
                DERObject keyInfo = derin.readObject();

                DERObjectIdentifier rsa_oid = PKCSObjectIdentifiers.rsaEncryption;
                AlgorithmIdentifier rsa = new AlgorithmIdentifier(rsa_oid);
                PrivateKeyInfo pkeyinfo = new PrivateKeyInfo(rsa, keyInfo);
                DERObject derkey = pkeyinfo.getDERObject();

                byte[] keyData = BouncyCastleUtil.toByteArray(derkey);

                // The DER object needs to be mangled to
                // create a proper ProvateKeyInfo object
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyData);
                KeyFactory kfac = KeyFactory.getInstance("RSA");

                return kfac.generatePrivate(spec);
            } catch (IOException e) {
                // that should never happen
                return null;
            }

        } else {
            return null;
        }
    }

    protected byte[] getEncoded(PrivateKey key) {
        String format = key.getFormat();
        if (format != null &&
                (format.equalsIgnoreCase("PKCS#8") ||
                        format.equalsIgnoreCase("PKCS8"))) {
            try {
                DERObject keyInfo = BouncyCastleUtil.toDERObject(key.getEncoded());
                PrivateKeyInfo pkey = new PrivateKeyInfo((ASN1Sequence) keyInfo);
                DERObject derKey = pkey.getPrivateKey();
                return BouncyCastleUtil.toByteArray(derKey);
            } catch (IOException e) {
                // that should never happen
                e.printStackTrace();
                return null;
            }
        } else if (format != null &&
                format.equalsIgnoreCase("PKCS#1") &&
                key instanceof RSAPrivateCrtKey) { // this condition will rarely be true
            RSAPrivateCrtKey pKey = (RSAPrivateCrtKey) key;
            RSAPrivateKeyStructure st =
                    new RSAPrivateKeyStructure(pKey.getModulus(),
                            pKey.getPublicExponent(),
                            pKey.getPrivateExponent(),
                            pKey.getPrimeP(),
                            pKey.getPrimeQ(),
                            pKey.getPrimeExponentP(),
                            pKey.getPrimeExponentQ(),
                            pKey.getCrtCoefficient());
            DERObject ob = st.getDERObject();

            try {
                return BouncyCastleUtil.toByteArray(ob);
            } catch (IOException e) {
                // that should never happen
                return null;
            }
        } else {
            return null;
        }
    }

    protected String getProvider() {
        return "BC";
    }
}
