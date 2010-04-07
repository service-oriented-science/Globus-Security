package org.globus.crux.osgi.proxy;

import java.util.Properties;

public interface Handler {

	void beforeMethod(HandlerContext context);

	void afterMethod(HandlerContext context);

	Object afterMethod(HandlerContext context, Object result);

	boolean shouldProxy(Object service, Properties props);

}
