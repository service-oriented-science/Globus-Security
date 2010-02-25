package org.globus.security.authorization.injection;

import org.globus.security.authorization.impl.GlobusContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BaseTestConfiguration {
	@Autowired GlobusContext context;
	
	@Bean public SampleServiceForInjection sampleService(){
		SampleServiceForInjection service = new SampleServiceForInjection();
		service.setContext(context);
		return service;
	}
}
