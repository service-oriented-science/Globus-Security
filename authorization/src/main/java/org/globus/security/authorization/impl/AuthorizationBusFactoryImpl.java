package org.globus.security.authorization.impl;

public class AuthorizationBusFactoryImpl extends AuthorizationBusFactory {

	@Override
	public DefaultAuthorizationBus createAuthorizationBus() {
		return new DefaultAuthorizationBus();
	}
	

}
