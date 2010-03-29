package org.globus.security;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.Subject;

public class GlobusTLSContext {
	private static ThreadLocal<Subject> containerSubjectHolder = new ThreadLocal<Subject>();
	private Subject containerSubject;
	private Subject peerSubject;
	private X509Certificate[] localCertChain;
	private X509Certificate[] peerCertChain;
	private Principal localPrincipal;
	private Principal peerPrincipal;
	private Date creationTime;
	private String sessionId;
	private String cipherSuite;
	private String protocol;
	private String peerHost;
	private int peerPort;
	private Logger logger = Logger.getLogger(getClass().getCanonicalName());

	public GlobusTLSContext(SSLSession sslSession) {
		containerSubject = new Subject();
		containerSubject.getPrincipals().add(sslSession.getLocalPrincipal());
		containerSubject.getPublicCredentials().add(
				getLocalCertChain(sslSession));
		GlobusTLSContext.containerSubjectHolder.set(containerSubject);
		peerSubject = new Subject();
		try {
			peerSubject.getPrincipals().add(sslSession.getPeerPrincipal());
		} catch (SSLPeerUnverifiedException e) {
			// We should already be verified, but if by some crazy chance we
			// aren't
			logger.log(Level.WARNING, e.getLocalizedMessage(), e);
		}
		peerSubject.getPublicCredentials().add(getPeerCertChain(sslSession));

		creationTime = new Date(sslSession.getCreationTime());
		try {
			sessionId = org.globus.util.StringUtils.getHexString(sslSession
					.getId());
		} catch (UnsupportedEncodingException e) {
			logger.log(Level.WARNING, e.getLocalizedMessage(), e);
		}
		cipherSuite = sslSession.getCipherSuite();
		protocol = sslSession.getProtocol();
		peerHost = sslSession.getPeerHost();
		peerPort = sslSession.getPeerPort();
	}

	public static Subject getCurrentContainerSubject() {
		return GlobusTLSContext.containerSubjectHolder.get();
	}

	public X509Certificate[] getLocalCertChain() {
		return localCertChain;
	}

	public X509Certificate[] getPeerCertChain() {
		return peerCertChain;
	}

	public Principal getLocalPrincipal() {
		return localPrincipal;
	}

	public Principal getPeerPrincipal() {
		return peerPrincipal;
	}

	public Date getCreationTime() {
		return creationTime;
	}

	public String getSessionId() {
		return sessionId;
	}

	public String getCipherSuite() {
		return cipherSuite;
	}

	public String getProtocol() {
		return protocol;
	}

	public String getPeerHost() {
		return peerHost;
	}

	public int getPeerPort() {
		return peerPort;
	}

	private X509Certificate[] getLocalCertChain(SSLSession sslSession) {
		try {
			Certificate[] javaxCerts = sslSession.getLocalCertificates();
			return processCerts(javaxCerts);
		} catch (Exception e) {
			logger.log(Level.WARNING, e.getLocalizedMessage(), e);
			return null;
		}
	}

	private X509Certificate[] getPeerCertChain(SSLSession sslSession) {
		Certificate[] javaxCerts;
		try {
			javaxCerts = sslSession.getPeerCertificates();
			return processCerts(javaxCerts);
		} catch (SSLPeerUnverifiedException e) {
			logger.log(Level.WARNING, e.getLocalizedMessage(), e);
			return null;
		} catch (CertificateEncodingException e) {
			logger.log(Level.WARNING, e.getLocalizedMessage(), e);
			return null;
		} catch (CertificateException e) {
			logger.log(Level.WARNING, e.getLocalizedMessage(), e);
			return null;
		}
	}

	private X509Certificate[] processCerts(
			java.security.cert.Certificate[] javaxCerts)
			throws CertificateException, CertificateEncodingException {
		if (javaxCerts == null || javaxCerts.length == 0)
			return null;
		int length = javaxCerts.length;
		X509Certificate[] javaCerts = new X509Certificate[length];
		java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
				.getInstance("X.509");
		for (int i = 0; i < length; i++) {
			byte bytes[] = javaxCerts[i].getEncoded();
			ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
			javaCerts[i] = (X509Certificate) cf.generateCertificate(stream);
		}
		return javaCerts;
	}

}
