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
package org.globus.security.bc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * A collection of various utility functions.
 *
 * @version ${version}
 * @since 1.0
 */
public final class BouncyCastleUtil {

    private BouncyCastleUtil() {

    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Converts given <code>DERObject</code> into a DER-encoded byte array.
     *
     * @param obj DERObject to convert.
     * @return the DER-encoded byte array
     * @throws IOException if conversion fails
     */
    public static byte[] toByteArray(DERObject obj)
            throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DEROutputStream der = new DEROutputStream(bout);
        der.writeObject(obj);
        return bout.toByteArray();
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

}
