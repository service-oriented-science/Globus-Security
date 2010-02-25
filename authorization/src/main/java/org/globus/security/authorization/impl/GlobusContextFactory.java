package org.globus.security.authorization.impl;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

import org.globus.util.ClassLoaderUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class GlobusContextFactory {

	public static final String FACTORY_PROPERTY_NAME = "org.globus.security.context.factory";
	protected static ThreadLocal<GlobusContext> localContext = new ThreadLocal<GlobusContext>();
	public static final String DEFAULT_CONTEXT_CLASS = SimpleGlobusContext.class.getCanonicalName();
	private static GlobusContextFactory defaultFactory;
	private static Logger logger = LoggerFactory.getLogger(GlobusContextFactory.class);

	protected abstract GlobusContext createContext();

	protected abstract GlobusContext createContext(Map<String, Object> properties);

	public static GlobusContext getContext(){
		if(defaultFactory == null){
			defaultFactory = newInstance();
		}
		return defaultFactory.createContext();
	}

	public static GlobusContextFactory newInstance() {
		return newInstance(null);
	}

	public static GlobusContextFactory newInstance(String className) {
		GlobusContextFactory instance = null;
		if (className == null) {
			ClassLoader loader = Thread.currentThread().getContextClassLoader();
			className = getContextFactoryClass(loader);
			if (className == null && loader != GlobusContextFactory.class.getClassLoader()) {
				className = getContextFactoryClass(GlobusContextFactory.class.getClassLoader());
			}
		}
		if (className == null) {
			 className = GlobusContextFactory.DEFAULT_CONTEXT_CLASS;
		}

		Class<? extends GlobusContextFactory> contextFactory;
		try {
			contextFactory = ClassLoaderUtils.loadClass(className, GlobusContextFactory.class).asSubclass(
					GlobusContextFactory.class);
			instance = contextFactory.newInstance();
		} catch (Exception ex) {
			logger.error("BUS_FACTORY_INSTANTIATION_EXC", ex);
			throw new RuntimeException(ex);
		}
		return instance;
	}

	private static String getContextFactoryClass(ClassLoader classLoader) {

		String busFactoryClass = null;
		String busFactoryCondition = null;

		// next check system properties
		busFactoryClass = System.getProperty(GlobusContextFactory.FACTORY_PROPERTY_NAME);
		if (isValidBusFactoryClass(busFactoryClass)) {
			return busFactoryClass;
		}
		//    
		try {
			// next, check for the services stuff in the jar file
			String serviceId = "META-INF/services/" + GlobusContextFactory.FACTORY_PROPERTY_NAME;
			InputStream is = null;

			if (classLoader == null) {
				classLoader = Thread.currentThread().getContextClassLoader();
			}

			if (classLoader == null) {
				is = ClassLoader.getSystemResourceAsStream(serviceId);
			} else {
				is = classLoader.getResourceAsStream(serviceId);
			}
			if (is == null) {
				serviceId = "META-INF/globus/" + GlobusContextFactory.FACTORY_PROPERTY_NAME;

				if (classLoader == null) {
					classLoader = Thread.currentThread().getContextClassLoader();
				}

				if (classLoader == null) {
					is = ClassLoader.getSystemResourceAsStream(serviceId);
				} else {
					is = classLoader.getResourceAsStream(serviceId);
				}
			}

			if (is != null) {
				BufferedReader rd = new BufferedReader(new InputStreamReader(is, "UTF-8"));
				busFactoryClass = rd.readLine();
				busFactoryCondition = rd.readLine();
				rd.close();
			}
			if (isValidBusFactoryClass(busFactoryClass)) {
				if (busFactoryCondition != null) {
					try {
						classLoader.loadClass(busFactoryCondition);
						return busFactoryClass;
					} catch (ClassNotFoundException e) {
						// TODO fix me
						return GlobusContextFactory.class.getCanonicalName();
					}
				} else {
					return busFactoryClass;
				}
			}
			return busFactoryClass;
		} catch (Exception ex) {
			logger.error("FAILED_TO_DETERMINE_BUS_FACTORY_EXC", ex);
		}
		return busFactoryClass;
	}

	private static boolean isValidBusFactoryClass(String busFactoryClassName) {
		return busFactoryClassName != null && !"".equals(busFactoryClassName);
	}
}
