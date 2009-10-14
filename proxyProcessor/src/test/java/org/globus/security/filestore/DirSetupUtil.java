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
package org.globus.security.filestore;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class DirSetupUtil {

    String[] fileNames;
    File tempDir;

    public DirSetupUtil(String[] fileNames_) {

        this.fileNames = fileNames_;
    }

    public void createTempDirectory() throws IOException {

        this.tempDir =
            File.createTempFile("temp", Long.toString(System.nanoTime()));

        if (!(tempDir.delete())) {
            throw new IOException(
                "Could not delete temp file: " +
                this.tempDir.getAbsolutePath());
        }

        if (!(tempDir.mkdir())) {
            throw new IOException(
                "Could not create temp directory: " +
                this.tempDir.getAbsolutePath());
        }

    }

    public void copy() throws Exception {

        for (int i = 0; i < this.fileNames.length; i++) {
            FileSetupUtil util = new FileSetupUtil(fileNames[i]);
            util.copyFileToTemp(this.tempDir);
        }
    }

    public File getTempDirectory() {

        return this.tempDir;
    }

    public String getTempDirectoryName() {
        if (this.tempDir != null) {
            return this.tempDir.getAbsolutePath();
        }
        return null;
    }

    public void delete() throws IOException {

        FileUtils.deleteDirectory(this.tempDir);
    }
}
