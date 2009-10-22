package org.globus.security.spring;

import org.springframework.beans.factory.FactoryBean;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Oct 21, 2009
 * Time: 3:38:47 PM
 * To change this template use File | Settings | File Templates.
 */
public class JKSFactory implements FactoryBean<KeyStore> {
    private String location;
    private String password;
    private String keyStoreType = "JKS";

    public KeyStore getObject() throws Exception {
        InputStream keystoreInputStream = null;
        if (location != null){
            keystoreInputStream = getResource(location);
        }
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(keystoreInputStream, password == null ? null : password.toCharArray());
        return keyStore;
    }

    private InputStream getResource(String source) throws IOException {
        InputStream is;
        try {
            URL url = new URL(source);
            is = url.openStream();
        } catch (MalformedURLException e) {
            File file = new File(source);
            if (file.exists()) {
                is = new FileInputStream(file);
            } else {
                is = getClass().getResource(source).openStream();
            }
        }
        return is;
    }

    public Class<? extends KeyStore> getObjectType() {
        return KeyStore.class;
    }

    public boolean isSingleton() {
        return true;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }
}
