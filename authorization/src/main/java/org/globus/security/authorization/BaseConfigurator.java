package org.globus.security.authorization;

import org.globus.security.authorization.impl.DefaultGlobusContext;
import org.globus.security.authorization.impl.GlobusContext;
import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.ThreadLocalTargetSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BaseConfigurator {

	@Bean public GlobusContext getContext(){
		ProxyFactoryBean factory = new ProxyFactoryBean();
		ThreadLocalTargetSource ts = new ThreadLocalTargetSource();
		ts.setTargetClass(DefaultGlobusContext.class);
		factory.setTargetSource(ts);
		return (GlobusContext) factory.getObject();		
	}
	
}
