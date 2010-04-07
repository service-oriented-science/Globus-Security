package org.globus.crux.gsi.server.internal;

import java.util.Map;

import javax.servlet.http.HttpServlet;

import org.apache.cxf.Bus;
import org.apache.cxf.databinding.DataBinding;
import org.apache.cxf.jaxb.JAXBDataBinding;
import org.apache.cxf.jaxws.JaxWsServerFactoryBean;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.osgi.framework.BundleContext;
import org.springframework.web.context.ContextLoaderListener;

public class JettyCruxServer {
	private CruxGSIServer server;

	public void initService(String path, BundleContext dswContext, BundleContext callingContext, Class<?> iClass, Map sd, Object serviceBean)
			throws Exception {
		CXFNonSpringServlet cxf = new CXFNonSpringServlet();
		this.registerServlet(cxf, 1, "Globus GSI Service", path, null);
		Bus bus = cxf.getBus();
		DataBinding databinding = new JAXBDataBinding();
		JaxWsServerFactoryBean factory = new JaxWsServerFactoryBean();
		factory.setBus(bus);
		factory.setServiceClass(iClass);
		factory.setAddress("/");
		factory.getServiceFactory().setDataBinding(databinding);
		factory.setServiceBean(serviceBean);
		ClassLoader oldClassLoader = Thread.currentThread()
				.getContextClassLoader();
		try {
//			String[] intents = applyIntents(dswContext, callingContext, factory
//					.getFeatures(), factory, sd);
//
//			// The properties for the EndpointDescription
//			Map<String, Object> endpointProps = createEndpointProps(sd, iClass,
//					new String[] { Constants.WS_CONFIG_TYPE }, address, intents);
//			EndpointDescription endpdDesc = null;
//
//			Thread.currentThread().setContextClassLoader(
//					ServerFactoryBean.class.getClassLoader());
//			Server server = factory.create();
//
//			// TODO: does this still make sense ?!?
//			registerStopHook(bus, httpService, server, contextRoot,
//					Constants.WS_HTTP_SERVICE_CONTEXT);
//
//			endpdDesc = new EndpointDescription(endpointProps);
//			exportRegistration.setServer(server);
//
//			// add the information on the new Endpoint to the export
//			// registration
//			exportRegistration.setEndpointdescription(endpdDesc);
//		} catch (IntentUnsatifiedException iue) {
//			exportRegistration.setException(iue);
		} finally {
			Thread.currentThread().setContextClassLoader(oldClassLoader);
		}

		// Map<String, String> props = new HashMap<String, String>();
		// props.put("contextConfigLocation", configPath);
		// registerServlet(cxf, 1, "CXF SERVLET", servicePath, props);
		//		
	}

	protected void registerServlet(HttpServlet servlet, int initOrder,
			String displayName, String path, Map<String, String> initProperties)
			throws Exception {
		ServletHolder holder = new ServletHolder(servlet);
		holder.setInitOrder(initOrder);
		holder.setDisplayName(displayName);
		holder.setInitParameters(initProperties);
		ServletContextHandler handler = new ServletContextHandler();
		handler.addEventListener(new ContextLoaderListener());
		handler.setInitParams(initProperties);
		handler.addServlet(holder, path);
		ClassLoader oldLoader = Thread.currentThread().getContextClassLoader();
		try {
			Thread.currentThread().setContextClassLoader(
					getClass().getClassLoader());
			server.getServer().addBean(handler);
		} finally {
			Thread.currentThread().setContextClassLoader(oldLoader);
		}
	}

	public CruxGSIServer getServer() {
		return server;
	}

	public void setServer(CruxGSIServer server) {
		this.server = server;
	}
	
	

}
