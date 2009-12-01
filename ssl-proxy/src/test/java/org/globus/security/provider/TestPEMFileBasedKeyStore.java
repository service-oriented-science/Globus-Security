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
package org.globus.security.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;

import org.globus.security.X509Credential;
import org.globus.security.filestore.DirSetupUtil;
import org.globus.security.filestore.FileSetupUtil;
import org.globus.security.util.CertificateLoadUtil;

import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class TestPEMFileBasedKeyStore {

    DirSetupUtil trustedDirectory;
    DirSetupUtil defaultTrustedDirectory;
    Vector<X509Certificate> testTrustedCertificates = new Vector<X509Certificate>();
    FileSetupUtil proxyFile1;
    FileSetupUtil proxyFile2;

    Map<FileSetupUtil, X509Certificate> trustedCertificates = new HashMap<FileSetupUtil, X509Certificate>();
    Map<FileSetupUtil, X509Credential> proxyCertificates = new HashMap<FileSetupUtil, X509Credential>();

    @BeforeClass
    public void setUp() throws Exception {

        ClassLoader loader = TestPEMFileBasedKeyStore.class.getClassLoader();

        String[] trustedCertFilenames =
                new String[]{"testTrustStore/1c3f2ca8.0", "testTrustStore/b38b4d8c.0"};
        this.trustedDirectory = new DirSetupUtil(trustedCertFilenames);
        this.trustedDirectory.createTempDirectory();
        this.trustedDirectory.copy();
        for (int i = 0; i < trustedCertFilenames.length; i++) {
            InputStream in = null;
            try {
                in = loader.getResourceAsStream(trustedCertFilenames[i]);

                if (in == null) {
                    throw new Exception("Unable to load: " + trustedCertFilenames[i]);
                }
                this.trustedCertificates.put(
                        this.trustedDirectory.getFileSetupUtil(trustedCertFilenames[i]),
                        CertificateLoadUtil.loadCertificate(in));
            } finally {
                if (in != null) {
                    in.close();
                }
            }
        }

        String[] defaultTrustedCert = new String[]{
                "testTrustStore/d1b603c3.0"};
        this.defaultTrustedDirectory = new DirSetupUtil(defaultTrustedCert);
        this.defaultTrustedDirectory.createTempDirectory();
        this.defaultTrustedDirectory.copy();
        for (int i = 0; i < defaultTrustedCert.length; i++) {
            InputStream in = null;
            try {
                in = loader.getResourceAsStream(defaultTrustedCert[i]);
                if (in == null) {
                    throw new Exception("Unable to load: " + defaultTrustedCert[i]);
                }
                this.trustedCertificates.put(
                        this.defaultTrustedDirectory.getFileSetupUtil(defaultTrustedCert[i]),
                        CertificateLoadUtil.loadCertificate(in));
            } finally {
                if (in != null) {
                    in.close();
                }
            }
        }


        String proxyFilename1 = "validatorTest/gsi2fullproxy.pem";
        this.proxyFile1 = new FileSetupUtil(proxyFilename1);
        this.proxyFile1.copyFileToTemp();
        this.proxyCertificates.put(this.proxyFile1,
                new X509Credential(loader.getResourceAsStream(proxyFilename1)));

        String proxyFilename2 = "validatorTest/gsi2limitedproxy.pem";
        this.proxyFile2 = new FileSetupUtil(proxyFilename2);
        this.proxyFile2.copyFileToTemp();
        this.proxyCertificates.put(this.proxyFile2,
                new X509Credential(loader.getResourceAsStream(proxyFilename2)));

        Security.addProvider(new GlobusProvider());
    }

    @Test
    public void testTrustedCerts() throws Exception {

        KeyStore store = KeyStore.getInstance("PEMFilebasedKeyStore", "Globus");

        // Parameters in properties file
        Properties properties = new Properties();
        properties.setProperty(FileBasedKeyStore.DEFAULT_DIRECTORY_KEY,
                this.defaultTrustedDirectory.getTempDirectoryName());
        properties.setProperty(FileBasedKeyStore.DIRECTORY_LIST_KEY, this.trustedDirectory.getTempDirectoryName());

        InputStream ins = null;
        try {
            ins = getProperties(properties);
            store.load(ins, null);
        } finally {
            if (ins != null) {
                ins.close();
            }
        }
        Enumeration aliases = store.aliases();
        assert (aliases.hasMoreElements());

        // alias to certificate test to be added.
        Iterator<FileSetupUtil> iterator = this.trustedCertificates.keySet().iterator();
        String alias = null;
        FileSetupUtil util = null;
        while (iterator.hasNext()) {
            util = iterator.next();
            alias = util.getTempFilename();
            Certificate certificate = store.getCertificate(alias);
            assert (certificate != null);
            assert ((certificate).equals(this.trustedCertificates.get(util)));
        }

        // test delete
        store.deleteEntry(alias);

        assert (store.getCertificate(alias) == null);

        assert (!util.getTempFile().exists());

    }

    @Test
    public void testProxyCerts() throws Exception {

        KeyStore store = KeyStore.getInstance("PEMFilebasedKeyStore", "Globus");

        // Parameters in properties file
        Properties properties = new Properties();
        properties.setProperty(FileBasedKeyStore.PROXY_FILENAME,
                this.proxyFile1.getAbsoluteFilename());
        InputStream ins = null;
        try {
            ins = getProperties(properties);
            store.load(ins, null);
        } finally {
            if (ins != null)
                ins.close();
        }

        Enumeration aliases = store.aliases();
        assert (aliases.hasMoreElements());

        // proxy file 1
        Key key = store.getKey(this.proxyFile1.getAbsoluteFilename(), null);
        assert (key != null);
        assert (key instanceof PrivateKey);

        Certificate[] certificates = store.getCertificateChain(this.proxyFile1.getAbsoluteFilename());
        assert (certificates != null);
        assert (certificates instanceof X509Certificate[]);

        //     assert (this.proxyCertificates.get(this.proxyFile1.getAbsoluteFilename()).equals(certificates[0]));

        // proxy file 2
        store.getKey(this.proxyFile2.getTempFilename(), null);
        assert (key != null);
        assert (key instanceof PrivateKey);

        certificates = store.getCertificateChain(this.proxyFile1.getAbsoluteFilename());
        assert (certificates != null);
        assert (certificates instanceof X509Certificate[]);

//        assert (this.proxyCertificates.get(this.proxyFile2.getTempFilename()).equals(certificates[0]));


        // test delete
        store.deleteEntry(this.proxyFile1.getAbsoluteFilename());

        assert (store.getCertificateChain(this.proxyFile1.getAbsoluteFilename()) == null);
        assert (!this.proxyFile1.getTempFile().exists());


    }

    private InputStream getProperties(Properties properties) throws Exception {

        ByteArrayOutputStream stream = null;
        ByteArrayInputStream ins = null;

        try {
            stream = new ByteArrayOutputStream();
            properties.store(stream, "Test Properties");

            // load all the CA files
            ins = new ByteArrayInputStream(stream.toByteArray());

        } finally {
            if (stream != null) {
                stream.close();
            }
        }
        return ins;
    }

    @AfterTest
    public void tearDown() throws Exception {
        this.defaultTrustedDirectory.delete();
        this.trustedDirectory.delete();
        this.proxyFile1.deleteFile();
        this.proxyFile2.deleteFile();
    }
}
