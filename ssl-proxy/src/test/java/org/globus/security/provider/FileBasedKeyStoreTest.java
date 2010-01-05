package org.globus.security.provider;

import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.testng.annotations.Test;

import java.io.*;
import java.security.KeyStore;
import java.util.Enumeration;
import java.util.Properties;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 1:01:14 PM
 * To change this template use File | Settings | File Templates.
 */
public class FileBasedKeyStoreTest {
    private FileBasedKeyStore keystore = new FileBasedKeyStore();
    private  PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();

    @Test
    public void testIO() throws Exception {
        InputStream is;
        ByteArrayOutputStream os;
        Properties props = new Properties();
        props.put(FileBasedKeyStore.KEY_FILENAME, "classpath:/key.pem");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        props.store(baos, "sample");
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        keystore.engineLoad(bais, null);
        Enumeration en = keystore.engineAliases();
        while(en.hasMoreElements()){
            System.out.println("en.nextElement().toString() = " + en.nextElement().toString());
        }
        os = new ByteArrayOutputStream();
//        keystore.engineStore(os, null);

//        keystore.engineStore(os, password);
    }
}
