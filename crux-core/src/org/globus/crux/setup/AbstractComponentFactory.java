package org.globus.crux.setup;

import java.util.Dictionary;
import java.util.Hashtable;

import org.osgi.framework.BundleContext;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.osgi.context.BundleContextAware;

public abstract class AbstractComponentFactory<T> implements
		ComponentFactory<T>, BundleContextAware, InitializingBean {

	private BundleContext context;

	public void setBundleContext(BundleContext arg0) {
		this.context = arg0;
	}

	public void afterPropertiesSet() throws Exception {
		Dictionary<String, Object> map = new Hashtable<String, Object>();
		map.put("org.globus.service.type", getMetadata().getType().getCanonicalName());
		map.put("org.globus.service.name", getMetadata().getName());
		context.registerService(ComponentFactory.class.getCanonicalName(),
				this, map);
	}
}
