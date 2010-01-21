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
package org.globus.security.filestore;

import org.globus.security.resources.ResourceTrustAnchor;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FilenameFilter;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;

import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
@Test(groups = {"AbstractFileBasedStore"})
public class TestFileBasedTrustAnchor {

    FileSetupUtil testCert1;

    @BeforeClass
    public void setUp() throws Exception {

        this.testCert1 = new FileSetupUtil("certificateUtilTest/1c3f2ca8.0");
    }


    @Test
    public void testGetTrustAnchor() throws Exception {

        this.testCert1.copyFileToTemp();

        String tempFileURL = this.testCert1.getURL().toExternalForm();

        ResourceTrustAnchor fileAnchor =
                new ResourceTrustAnchor("classpath:/certificateUtilTest/1c3f2ca8.0");

//        assert (fileAnchor != null);

        TrustAnchor anchor = fileAnchor.getSecurityObject();

        assert (anchor != null);

        X509Certificate cert = anchor.getTrustedCert();
        assert (cert != null);

        assertFalse(fileAnchor.hasChanged());

        anchor = fileAnchor.getSecurityObject();

        assert (anchor != null);

        assertFalse(fileAnchor.hasChanged());

        fileAnchor = new ResourceTrustAnchor(tempFileURL);

        this.testCert1.modifyFile();

        anchor = fileAnchor.getSecurityObject();

        assert (anchor != null);

        assertTrue(fileAnchor.hasChanged());

    }


    @Test
    public void testGetTrustAnchorFilter() {

        FilenameFilter filter = new TrustAnchorFilter();

        // Null checks
        boolean worked = false;
        try {
            filter.accept(null, null);
        } catch (IllegalArgumentException e) {
            worked = true;
        }
        assert worked;

        // null dir name
        assert (filter.accept(null, "foo.1"));

        // dir name ignored
        assert (filter.accept(new File("bar"), "foo.9"));

        // only single digit at end
        assertFalse(filter.accept(null, "foo.10"));

        // only single digit at end
        assertFalse(filter.accept(null, "foo.bar"));

        // the most common usage. *.0
        assertTrue(filter.accept(null, "foo.0"));

    }

    @AfterTest
    public void tearDown() {

        this.testCert1.deleteFile();
    }
}
