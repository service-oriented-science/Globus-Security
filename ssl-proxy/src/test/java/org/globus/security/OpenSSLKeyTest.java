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

import org.globus.crux.security.util.FileSetupUtil;
import org.globus.security.bc.BouncyCastleOpenSSLKey;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 31, 2009
 * Time: 9:54:25 AM
 * To change this template use File | Settings | File Templates.
 */
public class OpenSSLKeyTest {

    FileSetupUtil file;

    @BeforeClass
    public void setup() throws Exception {
        file = new FileSetupUtil("key.pem");
        file.copyFileToTemp();
        file.getTempFile();

    }

    @AfterClass
    public void cleanup() throws Exception {
        file.deleteFile();
    }

    @Test
    public void testOpenSSLKeyCreation() throws Exception {
        OpenSSLKey opensslkey = new BouncyCastleOpenSSLKey(file.getAbsoluteFilename());
        byte[] encoded = opensslkey.getEncoded();
        OpenSSLKey byteStreamInit = new BouncyCastleOpenSSLKey("RSA", encoded);
        assertEquals(opensslkey.getEncoded(), byteStreamInit.getEncoded());
        PrivateKey privateKey = opensslkey.getPrivateKey();
        OpenSSLKey privateKeyInit = new BouncyCastleOpenSSLKey(privateKey);
        assertEquals(opensslkey.getEncoded(), privateKeyInit.getEncoded());
        opensslkey.encrypt("password");
        assertFalse(opensslkey.getEncoded() == (encoded));
        byteStreamInit.encrypt("password");
        opensslkey = new BouncyCastleOpenSSLKey(opensslkey.getPrivateKey());
        opensslkey.decrypt("password");
        byteStreamInit = new BouncyCastleOpenSSLKey(byteStreamInit.getPrivateKey());
        byteStreamInit.decrypt("password");
        assertEquals(opensslkey.getEncoded(), byteStreamInit.getEncoded());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testNullByteStream() throws Exception {
        new BouncyCastleOpenSSLKey("RSA", null);
    }

    @Test(expectedExceptions = GeneralSecurityException.class)
    public void testEmptyByteStream() throws Exception {
        new BouncyCastleOpenSSLKey("RSA", new byte[]{});
    }

//    @Test
//    public void testNullAlgo() throws Exception{
//        new BouncyCastleOpenSSLKey(null, new byte[]{});
//    }
}
