package org.globus.crux.gsi.server;

import java.util.Map;
import java.util.Properties;

import javax.servlet.http.HttpServlet;

public interface CruxServer {

	public void registerServlet(HttpServlet servlet, String path);

	public void registerServlet(HttpServlet servlet, int initOrder,
			String displayName, String path, Map<String, String> initProperties);

}
