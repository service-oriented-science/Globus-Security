package org.globus.security;

import org.globus.security.bc.BouncyCastleOpenSSLKey;
import org.globus.security.filestore.FileSetupUtil;
import org.globus.security.util.FileUtil;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;

import static junit.framework.Assert.assertNotNull;
import static org.testng.Assert.*;

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
