package org.globus.crux.security;

import javax.security.auth.Subject;
import javax.xml.namespace.QName;

import org.globus.crux.security.attributes.EntityAttributes;


public interface GlobusContext {
	
	<T> T get(Class<T> type);
	
	Object get(String key);
	
	String getContainerId();
	
	Subject getContainerSubject();
	
	Subject getPeerSubject();
	
	Subject getServiceSubject();
	
	QName getOperation();

	EntityAttributes getContainerEntity();
}
