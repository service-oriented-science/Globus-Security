package org.globus.crux.gsi.server.internal;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.interceptor.LoggingInInterceptor;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;

public class CruxCXFServlet extends CXFNonSpringServlet {

	
	
	@Override
	public void loadBus(ServletConfig servletConfig) throws ServletException {
		super.loadBus(servletConfig);
		// You could add the endpoint publish codes here
		Bus bus = super.getBus();
		BusFactory.setDefaultBus(bus);
		bus.getInInterceptors().add(new LoggingInInterceptor());
		bus.getOutInterceptors().add(new LoggingOutInterceptor());
	}
}
