package org.globus.crux.osgi.proxy;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceEvent;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.hooks.service.EventHook;
import org.osgi.framework.hooks.service.FindHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.ProxyFactory;

public class CruxProxyServiceHook implements EventHook, FindHook {
	private BundleContext bc;
	private Logger logger = LoggerFactory.getLogger(getClass());
	private List<Handler> handlers;

	@SuppressWarnings("unchecked")
	public void event(ServiceEvent event, Collection contexts) {
		final ServiceReference serviceReference = event.getServiceReference();
		bc.getService(serviceReference);

		if (serviceReference.getProperty(Constants.DO_NOT_PROXY) == null
				&& serviceReference.getProperty(Constants.PROXY_SERVICE) == null
				&& serviceReference.getBundle().getBundleContext() != bc) {
			Bundle bundle = serviceReference.getBundle();

			switch (event.getType()) {
			case ServiceEvent.REGISTERED: {
				logger.trace("service registered");
				logger.debug("creating proxy for: " + bc.getService(serviceReference).getClass().getCanonicalName());
				String[] propertyKeys = serviceReference.getPropertyKeys();
				Properties properties = buildProps(propertyKeys, event);
				String[] interfaces = (String[]) serviceReference.getProperty("objectClass");
				Object service = createProxyService(serviceReference, properties);
				publishProxyService(bundle, service, interfaces, properties);
				break;
			}
			case ServiceEvent.UNREGISTERING: {
				// TODO
				break;
			}
			case ServiceEvent.MODIFIED:
			case ServiceEvent.MODIFIED_ENDMATCH: {
				// TODO
				break;
			}
			}
		}

	}

	private Object createProxyService(ServiceReference serviceReference, Properties props) {
		boolean shouldProxy = false;
		Object serviceObject = bc.getService(serviceReference);
		for (Handler handler : handlers) {
			if (handler.shouldProxy(serviceObject, props)) {
				shouldProxy = true;
				break;
			}
		}
		if (shouldProxy) {
			ProxyFactory proxyFac = new ProxyFactory(serviceObject);
			CruxProxyInterceptor advisor = new CruxProxyInterceptor(bc, serviceReference);
			proxyFac.addAdvice(advisor);
			return proxyFac.getProxy();
		} else {
			return serviceObject;
		}
	}

	private ServiceReference publishProxyService(Bundle bundleSource, Object serviceObject, String[] interfaces,
			Properties properties) {
		properties.put(Constants.PROXY_SERVICE, true);
		return bundleSource.getBundleContext().registerService(interfaces, serviceObject, properties).getReference();
	}

	private Properties buildProps(String[] propertyKeys, ServiceEvent event) {
		Properties properties = new Properties();
		for (String string : propertyKeys) {
			properties.put(string, event.getServiceReference().getProperty(string));
		}
		return properties;
	}

	@SuppressWarnings("unchecked")
	public void find(BundleContext context, String name, String filter, boolean allServices, Collection references) {
		try {
			if (this.bc.equals(bc) || bc.getBundle().getBundleId() == 0) {
				return;
			}

			logger.debug(" bundle : [" + bc.getBundle().getSymbolicName() + "] try to get reference  of " + name);
			Iterator<?> iterator = references.iterator();

			while (iterator.hasNext()) {
				ServiceReference sr = (ServiceReference) iterator.next();

				logger.debug("from bundle" + sr.getBundle().getSymbolicName());

				if (sr.getProperty(Constants.PROXY_REQUIRED) != null) {
					iterator.remove();
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public BundleContext getBundleContext() {
		return bc;
	}

	public void setBundleContext(BundleContext bc) {
		this.bc = bc;
	}

	class CruxProxyInterceptor implements MethodInterceptor {

		private BundleContext bundleContext;
		private ServiceReference serviceReference;
		private Logger logger = LoggerFactory.getLogger(getClass());

		public CruxProxyInterceptor(BundleContext context, ServiceReference serviceReference) {
			this.bundleContext = context;
			this.serviceReference = serviceReference;
		}

		public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
			logger.trace("Invoking authz handler on: " + this.serviceReference.toString());
			Object invoke = method.invoke(bundleContext.getService(serviceReference), args);
			logger.trace(this.serviceReference.toString() + " invoked.");
			return invoke;
		}

		public Object invoke(MethodInvocation invocation) throws Throwable {
			logger.trace("Invoking authz handler on: " + this.serviceReference.toString());
			HandlerContext context = new HandlerContext(invocation);
			for (Handler handler : handlers) {
				handler.beforeMethod(context);
			}
			Object invoke = invocation.proceed();
			logger.trace(this.serviceReference.toString() + " invoked.");
			for (Handler handler : handlers) {
				invoke = handler.afterMethod(context, invoke);
			}
			return invoke;
		}
	}

	public List<Handler> getHandlers() {
		return handlers;
	}

	public void setHandlers(List<Handler> handlers) {
		this.handlers = handlers;
	}
}
