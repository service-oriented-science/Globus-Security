package org.globus.crux;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class GlobusCruxServletListener implements ServletContextListener {
	private CruxFramework framework;

	public void contextDestroyed(ServletContextEvent arg0) {
		framework.stop();
	}

	public void contextInitialized(ServletContextEvent arg0) {
		framework = new CruxFramework(arg0.getServletContext());
		framework.start();
	}

}
