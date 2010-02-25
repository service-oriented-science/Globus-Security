package org.globus.security.authorization.cxf;

import java.util.Map;

import javax.security.auth.Subject;
import javax.xml.namespace.QName;

import org.apache.cxf.message.Message;
import org.apache.cxf.phase.PhaseInterceptorChain;
import org.globus.security.authorization.impl.GlobusContext;
import org.globus.security.authorization.impl.GlobusContextFactory;

public class CXFGlobusSecurityFactory extends GlobusContextFactory {

	@Override
	public GlobusContext createContext() {
		Message message = PhaseInterceptorChain.getCurrentMessage();
		return new CXFGlobusContext(message);
	}

	@Override
	public GlobusContext createContext(Map<String, Object> properties) {
		return this.createContext();
	}

	class CXFGlobusContext implements GlobusContext {

		private Message message;

		public CXFGlobusContext(Message message) {
			this.message = message;
		}

		public <T> T get(Class<T> type) {
			return message.get(type);
		}

		public Object get(String key) {
			return message.get(key);
		}

		public String getContainerId() {
			return (String) message.get("GLOBUS_CONTAINER_ID");
		}

		public Subject getContainerSubject() {
			return (Subject) message.get("GLOBUS_CONTAINER_SUBJECT");
		}

		public QName getOperation() {
			return (QName) message.get("GLOBUS_OPERATION");
		}

		public Subject getPeerSubject() {
			return (Subject) message.get("GLOBUS_PEER_SUBJECT");
		}

		public Subject getServiceSubject() {
			return (Subject) message.get("GLOBUS_SERVICE_SUBJECT");
		}

	}

}
