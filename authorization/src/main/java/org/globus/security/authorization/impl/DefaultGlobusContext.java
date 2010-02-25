package org.globus.security.authorization.impl;

import javax.security.auth.Subject;
import javax.xml.namespace.QName;

public class DefaultGlobusContext implements GlobusContext {
	private GlobusContext delegate;

	private GlobusContext getDelegate() {
		if (delegate == null) {
			delegate = GlobusContextFactory.newInstance().createContext();
		}
		return delegate;
	}

	public <T> T get(Class<T> type) {
		return getDelegate().get(type);
	}

	public Object get(String key) {
		return getDelegate().get(key);
	}

	public String getContainerId() {
		return getDelegate().getContainerId();
	}

	public Subject getContainerSubject() {
		return getDelegate().getContainerSubject();
	}

	public QName getOperation() {
		return getDelegate().getOperation();
	}

	public Subject getPeerSubject() {
		return getDelegate().getPeerSubject();
	}

	public Subject getServiceSubject() {
		return getDelegate().getServiceSubject();
	}

}
