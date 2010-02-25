package org.globus.security.authorization.impl;


public interface AuthorizationBus {
	
	String getId();
	
	AuthorizationEngine getAdminAuthorizationEngine();
	
	void setAdminAuthorizationEngine(AuthorizationEngine engine);
	
	AuthorizationEngine getContainerAuthorizationEngine();

}