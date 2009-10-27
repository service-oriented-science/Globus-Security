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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.util.Properties;

import org.globus.security.filestore.DirSetupUtil;

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

    @BeforeClass
    public void setUp() throws Exception {

        this.trustedDirectory = new DirSetupUtil(new String[]{"testTrustStore/1c3f2ca8.0",
                "testTrustStore/b38b4d8c.0"});
        this.trustedDirectory.createTempDirectory();
        this.trustedDirectory.copy();

        this.defaultTrustedDirectory = new DirSetupUtil(new String[]{
                "testTrustStore/d1b603c3.0"});
        this.defaultTrustedDirectory.createTempDirectory();
        this.defaultTrustedDirectory.copy();

        Security.addProvider(new TestGlobusProvider());
    }

    @Test
    public void testTrustedCerts() throws Exception {

        KeyStore store = KeyStore.getInstance("TestKeyStore", "GlobusTest");

        // Parameters in properties file
        Properties properties = new Properties();
        properties.setProperty(FileBasedKeyStore.DEFAULT_DIRECTORY_KEY,
                this.defaultTrustedDirectory.getTempDirectoryName());
        properties.setProperty(FileBasedKeyStore.DIRECTORY_LIST_KEY, this.trustedDirectory.getTempDirectoryName());
        OutputStream stream = new FileOutputStream("temp");
        properties.store(stream, "Test Properties");

        // load all the CA files
        store.load(new FileInputStream("temp"), null);

    }


}
