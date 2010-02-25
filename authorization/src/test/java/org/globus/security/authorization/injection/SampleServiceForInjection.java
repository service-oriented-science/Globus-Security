package org.globus.security.authorization.injection;

import javax.inject.Inject;

import org.globus.security.authorization.impl.GlobusContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SampleServiceForInjection {

	@Inject private GlobusContext context;
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	public void doSomthingWithContext(){
		logger.info("Starting to work with context");
		
		logger.info("Done working with context");
	}

	public GlobusContext getContext() {
		return context;
	}

	public void setContext(GlobusContext context) {
		this.context = context;
	}
	
	
	
}
