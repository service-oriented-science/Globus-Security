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

import org.globus.crux.security.util.FileSetupUtil;
import org.globus.security.stores.ResourceCRL;
import org.springframework.core.io.FileSystemResource;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.security.cert.X509CRL;

import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
@Test(groups = {"AbstractFileBasedStore"})
public class TestFileBasedCRL {

    FileSetupUtil testCrl1;

    @BeforeClass
    public void setUp() throws Exception {

        this.testCrl1 = new FileSetupUtil("certificateUtilTest/validCrl.r0");
    }


    @Test
    public void testGetCrl() throws Exception {

        this.testCrl1.copyFileToTemp();

        String tempFileName = this.testCrl1.getAbsoluteFilename();

        ResourceCRL fileCrl = new ResourceCRL(new FileSystemResource(new File(tempFileName)));

//        assert (fileCrl != null);

        X509CRL crl = fileCrl.getCrl();

        assert (crl != null);

        assertFalse(fileCrl.hasChanged());

        crl = fileCrl.getCrl();

        assert (crl != null);

        assertFalse(fileCrl.hasChanged());

        this.testCrl1.modifyFile();

        crl = fileCrl.getCrl();

        assert (crl != null);

        assertTrue(fileCrl.hasChanged());
    }

//    @Test
//    public void testGetCrlFilter() {
//
//        FilenameFilter filter = FileBasedCRL.getCrlFilter();
//
//        // Null checks
//        boolean worked = false;
//        try {
//            filter.accept(null, null);
//        } catch (IllegalArgumentException e) {
//            worked = true;
//        }
//        assert worked;
//
//        // null dir name
//        assert (filter.accept(null, "foo.r1"));
//
//        // dir name ignored
//        assert (filter.accept(new File("bar"), "foo.r9"));
//
//        // only single digit at end
//        assertFalse(filter.accept(null, "foo.r10"));
//
//        // only single digit at end
//        assertFalse(filter.accept(null, "foo.rbar"));
//
//        // the most common usage. *.0
//        assertTrue(filter.accept(null, "foo.r0"));
//
//    }

    @AfterTest
    public void tearDown() throws Exception {
        this.testCrl1.deleteFile();
    }

}
