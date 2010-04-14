package org.globus.security.authorization;

import javax.security.auth.Subject;
import javax.xml.namespace.QName;


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
