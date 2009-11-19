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

import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileSetupUtil {

    String filename;
    File tempFile;

    public FileSetupUtil(String filename_) {

        this.filename = filename_;
    }

    public File getTempFile() {
        return this.tempFile;
    }

    public void copyFileToTemp() throws Exception {

        copyFileToTemp(null);
    }

    public void copyFileToTemp(File dir) throws Exception {

        InputStream in = null;
        FileWriter writer = null;
        try {
            ClassLoader loader =
                    FileSetupUtil.class.getClassLoader();
            in = loader.getResourceAsStream(this.filename);
            int index = filename.lastIndexOf(".");
            this.tempFile = File.createTempFile("globusSecurityTest",
                    filename.substring(index,
                            filename.length()),
                    dir);
            writer = new FileWriter(this.tempFile);
            int c;
            while ((c = in.read()) != -1) {
                writer.write(c);
            }
        } finally {
            if (in != null) {
                in.close();
            }

            if (writer != null) {
                writer.close();
            }
        }
    }

    public String getAbsoluteFilename() {
        return this.tempFile.getAbsolutePath();
    }

    public String getTempFilename() {
        return this.tempFile.getName();
    }

    public void deleteFile() {
        if (this.tempFile != null) {
            this.tempFile.delete();
        }
    }

    public void modifyFile() throws Exception {
        if (this.tempFile != null) {
            // FIXME: only way for modified time to have some delta
            Thread.sleep(1000);
            FileWriter writer = null;
            try {
                writer = new FileWriter(this.tempFile,
                        true);

                writer.write("\n");
            } finally {
                if (writer != null) {
                    writer.close();
                }
            }
        }
    }

}
