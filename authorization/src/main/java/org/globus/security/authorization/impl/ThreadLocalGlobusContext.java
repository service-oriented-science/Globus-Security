package org.globus.security.authorization.impl;

import javax.security.auth.Subject;
import javax.xml.namespace.QName;

import org.globus.security.authorization.EntityAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ThreadLocalGlobusContext extends SimpleGlobusContext {
	private final ThreadLocal<SimpleGlobusContext> localContext = new ThreadLocal<SimpleGlobusContext>();
	private int instanceCount;
	private Logger logger = LoggerFactory.getLogger(getClass());

	private SimpleGlobusContext getInstance() {
		SimpleGlobusContext instance = localContext.get();
		if (instance == null) {
			instanceCount++;
			if (logger.isDebugEnabled()) {
				logger.debug("Creating new instance of SimpleGlobusContext for thread: {}", Thread.currentThread()
						.getName());
			}
			instance = new SimpleGlobusContext();
			localContext.set(instance);
		}
		return instance;
	}
	
	public int getInstanceCount(){
		return instanceCount;
	}
	
	public void destroy(){
		localContext.set(null);
	}

	@Override
	public <T> void addProperty(Class<T> clazz, T value) {
		getInstance().addProperty(clazz, value);
	}

	@Override
	public void addProperty(String key, Object value) {
		getInstance().addProperty(key, value);
	}

	@Override
	public <T> T get(Class<T> type) {
		return getInstance().get(type);
	}

	@Override
	public void setContainerEntity(EntityAttributes containerEntityParam) {
		getInstance().setContainerEntity(containerEntityParam);
	}

	@Override
	public void setContainerId(String containerId) {
		getInstance().setContainerId(containerId);
	}

	@Override
	public void setContainerSubject(Subject containerSubject) {
		getInstance().setContainerSubject(containerSubject);
	}

	@Override
	public void setOperation(QName operation) {
		getInstance().setOperation(operation);
	}

	@Override
	public void setPeerSubject(Subject peerSubject) {
		getInstance().setPeerSubject(peerSubject);
	}

	@Override
	public void setServiceSubject(Subject serviceSubject) {
		getInstance().setServiceSubject(serviceSubject);
	}

	@Override
	public <T> T get(String key, Class<T> type) {
		return getInstance().get(key, type);
	}

	@Override
	public Object get(String key) {
		return getInstance().get(key);
	}

	@Override
	public EntityAttributes getContainerEntity() {
		return getInstance().getContainerEntity();
	}

	@Override
	public String getContainerId() {
		return getInstance().getContainerId();
	}

	@Override
	public Subject getContainerSubject() {
		return getInstance().getContainerSubject();
	}

	@Override
	public QName getOperation() {
		return getInstance().getOperation();
	}

	@Override
	public Subject getPeerSubject() {
		return getInstance().getPeerSubject();
	}

	@Override
	public Subject getServiceSubject() {
		return getInstance().getServiceSubject();
	}
}
