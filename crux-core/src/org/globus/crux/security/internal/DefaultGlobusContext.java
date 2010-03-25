package org.globus.crux.security.internal;

import javax.security.auth.Subject;
import javax.xml.namespace.QName;

import org.globus.crux.security.GlobusContext;
import org.globus.crux.security.attributes.EntityAttributes;

public class DefaultGlobusContext implements GlobusContext {

	public <T> T get(Class<T> type) {
		// TODO Auto-generated method stub
		return null;
	}

	public Object get(String key) {
		// TODO Auto-generated method stub
		return null;
	}

	public EntityAttributes getContainerEntity() {
		// TODO Auto-generated method stub
		return null;
	}

	public String getContainerId() {
		// TODO Auto-generated method stub
		return null;
	}

	public Subject getContainerSubject() {
		// TODO Auto-generated method stub
		return null;
	}

	public QName getOperation() {
		// TODO Auto-generated method stub
		return null;
	}

	public Subject getPeerSubject() {
		// TODO Auto-generated method stub
		return null;
	}

	public Subject getServiceSubject() {
		// TODO Auto-generated method stub
		return null;
	}

}
