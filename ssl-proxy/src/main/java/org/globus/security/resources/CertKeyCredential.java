package org.globus.security.resources;

import org.apache.commons.io.FileUtils;
import org.globus.security.CredentialException;
import org.globus.security.X509Credential;
import org.globus.security.filestore.FileStoreException;
import org.springframework.core.io.Resource;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 5, 2010
 * Time: 4:53:39 PM
 * To change this template use File | Settings | File Templates.
 */

public class CertKeyCredential implements SecurityObjectWrapper<X509Credential>, Storable, CredentialWrapper {

    private long certLastModified = -1;
    private long keyLastModified = -1;

    protected Resource certFile = null;
    protected Resource keyFile = null;

    private X509Credential credential;

    private boolean changed;

    public CertKeyCredential(Resource certFile, Resource keyFile) throws ResourceStoreException {
        init(certFile, keyFile);
    }

    public CertKeyCredential(Resource certFile, Resource keyFile, X509Credential credential) throws ResourceStoreException{
        this.certFile = certFile;
        try{
        if(!certFile.exists()){
            FileUtils.touch(certFile.getFile());
            this.certLastModified = certFile.lastModified();
        }
        this.keyFile = keyFile;
        if(!keyFile.exists()){
            FileUtils.touch(keyFile.getFile());
            this.keyLastModified = keyFile.lastModified();
        }
        }catch(IOException e){
            throw new ResourceStoreException(e);
        }
        this.credential = credential;
    }

    protected void init(Resource certFile_, Resource keyFile_) throws ResourceStoreException {

        if ((certFile_ == null) || (keyFile_ == null)) {
            throw new IllegalArgumentException();
        }

        this.certFile = certFile_;
        this.keyFile = keyFile_;
        this.credential = createObject(this.certFile, this.keyFile);
        try {
            this.certLastModified = this.certFile.lastModified();
            this.keyLastModified = this.keyFile.lastModified();
        } catch (IOException ioe) {
            throw new ResourceStoreException(ioe);
        }
    }

    protected void init(Resource certFile_, Resource keyFile_, X509Credential object_) throws ResourceStoreException {

        if (object_ == null) {
            // FIXME: better exception?
            throw new IllegalArgumentException("Object cannot be null");
        }
        this.credential = object_;
        this.certFile = certFile_;
        this.keyFile = keyFile_;
    }


    public void refresh() throws ResourceStoreException {
        long cLatestLastModified;
        long kLatestLastModified;
        this.changed = false;
        try {
            cLatestLastModified = this.certFile.lastModified();
            kLatestLastModified = this.keyFile.lastModified();
        } catch (IOException ioe) {
            throw new ResourceStoreException(ioe);
        }
        if ((this.certLastModified < cLatestLastModified) ||
                (this.keyLastModified < kLatestLastModified)) {
            this.credential = createObject(this.certFile, this.keyFile);
            this.certLastModified = cLatestLastModified;
            this.keyLastModified = kLatestLastModified;
            this.changed = true;
        }
    }

    public Resource getCertificateFile() {
        return this.certFile;
    }

    public Resource getKeyFile() {
        return this.keyFile;
    }

    // for creation of credential from a file

    protected X509Credential createObject(Resource certFile, Resource keyFile)
            throws ResourceStoreException {
        InputStream certIns;
        InputStream keyIns;
        try {
            certIns = certFile.getInputStream();
            keyIns = keyFile.getInputStream();
            return new X509Credential(certIns, keyIns);
        } catch (FileNotFoundException e) {
            throw new ResourceStoreException(e);
        } catch (CredentialException e) {
            throw new ResourceStoreException(e);
        } catch (IOException ioe) {
            throw new ResourceStoreException(ioe);
        }
    }

    public X509Credential getSecurityObject() throws ResourceStoreException {
        refresh();
        return credential;
    }

    public boolean hasChanged() {
        return this.changed;
    }

    public X509Credential getCredential() throws ResourceStoreException {
        return getSecurityObject();
    }

    public void store() throws ResourceStoreException {
        try {
            this.credential.writeToFile(this.certFile.getFile(), this.keyFile.getFile());
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        } catch (CertificateEncodingException e) {
            throw new ResourceStoreException(e);
        }
    }

    public String getAlias() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
