package org.globus.security.filestore;

import java.io.File;
import java.io.FilenameFilter;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 11:28:38 AM
 * To change this template use File | Settings | File Templates.
 */
public class SigningPolicyFilter implements FilenameFilter {

    public final static String SIGNING_POLICY_FILE_SUFFIX = ".signing_policy";

    public boolean accept(File dir, String file) {
        if (file == null) {
            throw new IllegalArgumentException();
        }
        return file.endsWith(SIGNING_POLICY_FILE_SUFFIX);
    }
}