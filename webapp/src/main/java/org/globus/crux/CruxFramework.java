package org.globus.crux;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.servlet.ServletContext;

import org.apache.felix.framework.Felix;
import org.apache.felix.framework.util.FelixConstants;

public class CruxFramework {
	private ServletContext context;
	private Felix felix;

	public CruxFramework(ServletContext context) {
		this.context = context;
	}

	public void start() {
		try {
			doStart();
		} catch (Exception e) {
			log("Failed to start framework", e);
		}
	}

	public void stop() {
		try {
			doStop();
		} catch (Exception e) {
			log("Error stopping framework", e);
		}
	}

	private void doStart() throws Exception {
		Felix tmp = new Felix(createConfig());
		tmp.start();
		this.felix = tmp;
		log("OSGi framework started", null);
	}

	private void doStop() throws Exception {
		if (this.felix != null) {
			this.felix.stop();
		}

		log("OSGi framework stopped", null);
	}

	private Map<String, Object> createConfig() throws Exception {
		Properties props = new Properties();
		props.load(this.context
				.getResourceAsStream("/WEB-INF/framework.properties"));

		HashMap<String, Object> map = new HashMap<String, Object>();
		for (Object key : props.keySet()) {
			map.put(key.toString(), props.get(key));
		}

		map.put(FelixConstants.SYSTEMBUNDLE_ACTIVATORS_PROP, Arrays
				.asList(new CruxActivator(this.context)));
		return map;
	}

	private void log(String message, Throwable cause) {
		this.context.log(message, cause);
	}

}
