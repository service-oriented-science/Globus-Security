package org.globus.crux.osgi.proxy;

import org.aopalliance.intercept.MethodInvocation;

public class HandlerContext {
	private MethodInvocation invocation;

	public HandlerContext(MethodInvocation invoke) {
		this.invocation = invoke;
	}

	public String getMethodName() {
		return invocation.getMethod().getDeclaringClass().getCanonicalName() + "." + invocation.getMethod().getName();
	}
	

	public Object[] getParameters() {
		return invocation.getArguments();
	}

	
	public Object getService() {
		return invocation.getThis();
	}

}
