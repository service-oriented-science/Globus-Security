package org.globus.security.authorization.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.imageio.spi.ServiceRegistry;

import org.globus.security.authorization.AuthorizationEngineSpi;
import org.globus.security.authorization.InitializeException;
import org.globus.util.I18nUtil;

public class AuthorizationEngineFactory {

	private ServiceRegistry registry;
	private I18nUtil i18n = I18nUtil.getI18n("errors.properties");
	private static AuthorizationEngineFactory instance;
	private Map<String, AuthorizationEngine> cachedEngines = new HashMap<String, AuthorizationEngine>();

	private AuthorizationEngineFactory() {
		List<Class<?>> interfaces = new ArrayList<Class<?>>();
		interfaces.add(AuthorizationEngineSpi.class);
		registry = new ServiceRegistry(interfaces.iterator());
	}

	public AuthorizationEngine getEngine(String algorithm) throws InitializeException {
		return getEngine(algorithm, true);
	}

	public AuthorizationEngine createEngine(String algorithm) throws InitializeException {
		Iterator<AuthorizationEngineSpi> impls = registry.getServiceProviders(AuthorizationEngineSpi.class,
				new AlgorithmFilter(algorithm), false);
		if (impls.hasNext()) {
			return new AuthorizationEngine(impls.next());
		} else {
			throw new InitializeException(i18n.getMessage("invalidAuthzAlg"));
		}
	}

	public static AuthorizationEngine getEngine(String algorithm, boolean createIfNecessary) throws InitializeException {
		if (instance == null) {
			instance = new AuthorizationEngineFactory();
		}
		AuthorizationEngine engine = instance.cachedEngines.get(algorithm);
		if (engine != null) {
			return engine;
		} else if (createIfNecessary) {
			return instance.createEngine(algorithm);
		} else {
			return null;
		}
	}

	class AlgorithmFilter implements ServiceRegistry.Filter {
		private String algorithm;

		public AlgorithmFilter(String algorithm) {
			this.algorithm = algorithm;
		}

		public boolean filter(Object provider) {
			if (!(provider instanceof AuthorizationEngineSpi)) {
				return false;
			}
			return ((AuthorizationEngineSpi) provider).getAlgorithm().equals(this.algorithm);
		}
	}
}
