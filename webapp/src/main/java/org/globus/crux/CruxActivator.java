package org.globus.crux;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.ServletContext;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class CruxActivator implements BundleActivator {

	private final ServletContext servletContext;

	public CruxActivator(ServletContext servletContext) {
		this.servletContext = servletContext;
	}

	public void start(BundleContext context) throws Exception {
		servletContext.setAttribute(BundleContext.class.getName(), context);

		ArrayList<Bundle> installed = new ArrayList<Bundle>();
		for (URL url : findBundles()) {
			this.servletContext.log("Installing bundle [" + url + "]");
			Bundle bundle = context.installBundle(url.toExternalForm());
			installed.add(bundle);
		}

		for (Bundle bundle : installed) {
			bundle.start();
		}
	}

	public void stop(BundleContext context) throws Exception {
	}

	private List<URL> findBundles() throws Exception {
		ArrayList<URL> list = new ArrayList<URL>();
		Collection<?> bundles = this.servletContext.getResourcePaths("/WEB-INF/bundles/");
		for (Object o : bundles) {
			String name = (String) o;
			if (name.endsWith(".jar")) {
				URL url = this.servletContext.getResource(name);
				if (url != null) {
					list.add(url);
				}
			}
		}

		return list;
	}
}
