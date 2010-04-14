package org.globus.security.authorization.impl;

import javax.security.auth.Subject;
import javax.xml.namespace.QName;

import org.globus.security.authorization.EntityAttributes;

public interface GlobusContext {

	<T> T get(Class<T> type);

	<T> T get(String key, Class<T> type);

	Object get(String key);

	String getContainerId();

	Subject getContainerSubject();

	Subject getPeerSubject();

	Subject getServiceSubject();

	QName getOperation();

	EntityAttributes getContainerEntity();

}
