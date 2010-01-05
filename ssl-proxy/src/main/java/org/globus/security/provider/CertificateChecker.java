package org.globus.security.provider;

import org.globus.security.Constants;

import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 12:01:07 PM
 * To change this template use File | Settings | File Templates.
 */
public interface CertificateChecker {
    void invoke(X509Certificate cert, Constants.CertificateType certType) throws CertPathValidatorException;
}
