package org.globus.security.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthorizationBaseConfiguration {

	private @Autowired ContainerCredential container;
	
	
}
