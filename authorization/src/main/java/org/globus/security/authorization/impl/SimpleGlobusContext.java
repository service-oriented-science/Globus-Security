package org.globus.security.authorization.impl;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.xml.namespace.QName;

public class SimpleGlobusContext implements GlobusContext{
	private Map<String, Object> propMap = new HashMap<String, Object>();
	private String containerId;
	private Subject containerSubject;
	private QName operation;
	private Subject peerSubject;
	private Subject serviceSubject;
	
	@SuppressWarnings("unchecked")
	public <T> T get(Class<T> type) {
		return (T) propMap.get(type.getCanonicalName());
	}

	public void addProperty(String key, Object value){
		this.propMap.put(key, value);
	}
	
	public <T> void addProperty(Class<T> clazz, T value){
		this.propMap.put(clazz.getCanonicalName(), value);
	}
	
	public Object get(String key) {
		return propMap.get(key);
	}

	public String getContainerId() {
		return containerId;
	}

	public Subject getContainerSubject() {
		return containerSubject;
	}

	public QName getOperation() {
		return operation;
	}

	public Subject getPeerSubject() {
		return peerSubject;
	}

	public Subject getServiceSubject() {
		return serviceSubject;
	}

	public void setContainerId(String containerId) {
		this.containerId = containerId;
	}

	public void setContainerSubject(Subject containerSubject) {
		this.containerSubject = containerSubject;
	}

	public void setOperation(QName operation) {
		this.operation = operation;
	}

	public void setPeerSubject(Subject peerSubject) {
		this.peerSubject = peerSubject;
	}

	public void setServiceSubject(Subject serviceSubject) {
		this.serviceSubject = serviceSubject;
	}
	
	

	
}
