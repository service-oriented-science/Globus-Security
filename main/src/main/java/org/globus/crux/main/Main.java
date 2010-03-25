package org.globus.crux.main;

import java.lang.management.ManagementFactory;

import org.eclipse.jetty.jmx.MBeanContainer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.webapp.WebAppContext;

public class Main {

	public static void main(String[] args) throws Exception {
		
		Server server = new Server(8080);
		MBeanContainer mbContainer = new MBeanContainer(ManagementFactory
				.getPlatformMBeanServer());
		server.getContainer().addEventListener(mbContainer);
		server.addBean(mbContainer);
		mbContainer.addBean(Log.getLog());
		WebAppContext context = new WebAppContext();
		context.setResourceBase("webapp");
		context.setContextPath("/");
		context.setParentLoaderPriority(true);

		server.setHandler(context);

		server.start();
		server.join();
	}
}
