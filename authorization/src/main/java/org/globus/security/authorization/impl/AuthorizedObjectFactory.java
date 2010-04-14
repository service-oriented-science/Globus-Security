package org.globus.security.authorization.impl;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.globus.security.authorization.GlobusContext;
import org.springframework.aop.framework.ProxyFactory;

public class AuthorizedObjectFactory {
	private AuthorizationHandler handler;
	private GlobusContext context;

	public Object addAuthorization(Object o) {
		ProxyFactory factory = new ProxyFactory(o);
		factory.addAdvice(new MethodInterceptor() {

			public Object invoke(MethodInvocation arg0) throws Throwable {
				handler.handle(context);
				return arg0.getMethod().invoke(arg0.getThis(), arg0.getArguments());
			}
		});
		return factory.getProxy();
	}

	public void setGlobusContext(GlobusContext context){
		this.context = context;
	}
	
	public AuthorizationHandler getHandler() {
		return handler;
	}

	public void setHandler(AuthorizationHandler handler) {
		this.handler = handler;
	}
}
