package org.globus.crux.osgi.proxy;

import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoggingProxyHandler implements Handler {
	Logger logger = LoggerFactory.getLogger(getClass());
	
	public void afterMethod(HandlerContext context) {
		// TODO Auto-generated method stub
	}

	public Object afterMethod(HandlerContext context, Object result) {
		logger.debug("Finished executing: " +  context.getMethodName());
		return result;
	}

	public void beforeMethod(HandlerContext context) {
		logger.debug("Started executing: " +  context.getMethodName());
		

	}

	public boolean shouldProxy(Object service, Properties props) {
		return true;
	}

}
