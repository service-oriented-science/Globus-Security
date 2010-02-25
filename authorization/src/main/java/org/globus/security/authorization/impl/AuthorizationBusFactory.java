package org.globus.security.authorization.impl;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.globus.util.ClassLoaderUtils;
import org.globus.util.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AuthorizationBusFactory {

	private static final String DEFAULT_BUS_FACTORY = AuthorizationBusFactoryImpl.class.getCanonicalName();
	private static final String BUS_FACTORY_KEY = AuthorizationBusFactory.class.getCanonicalName();

	private static Logger logger = LoggerFactory.getLogger(AuthorizationBusFactory.class);

	private static InheritableThreadLocal<DefaultAuthorizationBus> localBus = new InheritableThreadLocal<DefaultAuthorizationBus>();

	private static DefaultAuthorizationBus defaultBus;

	private static I18n i18n = I18n.getI18n("errors.properties");

	public abstract DefaultAuthorizationBus createAuthorizationBus();

	public static void setLocalDefaultBus(DefaultAuthorizationBus newBus) {
		AuthorizationBusFactory.localBus.set(newBus);
	}

	public AuthorizationBus getLocalDefaultBus() {
		return getDefaultBus(true);
	}

	public AuthorizationBus getLocalDefaultBus(boolean createIfNecessary) {
		if (createIfNecessary && localBus.get() == null) {
			localBus.set(getDefaultBus(createIfNecessary));
		}
		return localBus.get();
	}

	public DefaultAuthorizationBus getDefaultBus(boolean createIfNecessary) {
		if (AuthorizationBusFactory.defaultBus == null) {
			if (createIfNecessary) {
				AuthorizationBusFactory.defaultBus = createAuthorizationBus();
			}
		}
		return AuthorizationBusFactory.defaultBus;
	}

	public AuthorizationBus getDefaultBus() {
		return getDefaultBus(true);
	}

	public void setDefaultBus(DefaultAuthorizationBus newBus) {
		AuthorizationBusFactory.defaultBus = newBus;
	}

	public static AuthorizationBusFactory newInstance() {
		return newInstance(null);
	}

	public static AuthorizationBusFactory newInstance(String className) {
		AuthorizationBusFactory instance = null;
		if (className == null) {
			ClassLoader loader = Thread.currentThread().getContextClassLoader();
			className = getBusFactoryClass(loader);
			if (className == null && loader != AuthorizationBusFactory.class.getClassLoader()) {
				className = getBusFactoryClass(AuthorizationBusFactory.class.getClassLoader());
			}
		}
		if (className == null) {
			className = AuthorizationBusFactory.DEFAULT_BUS_FACTORY;
		}
		Class<? extends AuthorizationBusFactory> busFactoryClass;
		try {
			busFactoryClass = ClassLoaderUtils.loadClass(className, AuthorizationBusFactory.class).asSubclass(
					AuthorizationBusFactory.class);
			instance = busFactoryClass.newInstance();
		} catch (Exception ex) {
			// LogUtils.log(LOG, Level.SEVERE, "BUS_FACTORY_INSTANTIATION_EXC",
			// ex);
			logger.error(i18n.getMessage("BUS_FACTORY_INSTANTIATION_EXC"), ex);
			throw new RuntimeException(ex);
		}
		return instance;
	}

	private static String getBusFactoryClass(ClassLoader classLoader) {

		String busFactoryClass = null;
		String busFactoryCondition = null;

		// next check system properties
		busFactoryClass = System.getProperty(AuthorizationBusFactory.BUS_FACTORY_KEY);
		if (isValidBusFactoryClass(busFactoryClass)) {
			return busFactoryClass;
		}

		try {
			// next, check for the services stuff in the jar file
			String serviceId = "META-INF/services/" + AuthorizationBusFactory.BUS_FACTORY_KEY;
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
				serviceId = "META-INF/cxf/" + AuthorizationBusFactory.BUS_FACTORY_KEY;

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
						return DEFAULT_BUS_FACTORY;
					}
				} else {
					return busFactoryClass;
				}
			}
			return busFactoryClass;
		} catch (Exception ex) {
			logger.error(i18n.getMessage("FAILED_TO_DETERMINE_BUS_FACTORY_EXC"), ex);
		}
		return busFactoryClass;
	}

	private static boolean isValidBusFactoryClass(String busFactoryClassName) {
		return busFactoryClassName != null && !"".equals(busFactoryClassName);
	}

}
