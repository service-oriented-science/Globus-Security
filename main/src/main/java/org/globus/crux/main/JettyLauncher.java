package org.globus.crux.main;

import java.util.Collection;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

public class JettyLauncher implements InitializingBean, DisposableBean {

	Server server;
	Collection<Connector> connectors;

	public void afterPropertiesSet() throws Exception {
		server = new Server();
		for (Connector connector : connectors) {
			server.addConnector(connector);
		}
		server.start();
		server.join();
	}

	public void destroy() throws Exception {
		server.stop();
	}

	public Collection<Connector> getConnectors() {
		return connectors;
	}

	public void setConnectors(Collection<Connector> connectors) {
		this.connectors = connectors;
	}
}
