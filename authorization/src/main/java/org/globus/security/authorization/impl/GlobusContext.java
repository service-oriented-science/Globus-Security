package org.globus.security.authorization.impl;

import javax.security.auth.Subject;
import javax.xml.namespace.QName;


public interface GlobusContext {
	
	<T> T get(Class<T> type);
	
	Object get(String key);
	
	String getContainerId();
	
	Subject getContainerSubject();
	
	Subject getPeerSubject();
	
	Subject getServiceSubject();
	
	QName getOperation();

}
