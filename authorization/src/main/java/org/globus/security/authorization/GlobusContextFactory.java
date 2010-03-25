package org.globus.security.authorization;

import org.globus.security.authorization.impl.DefaultGlobusContext;
import org.globus.security.authorization.impl.GlobusContext;

public class GlobusContextFactory {

	public static GlobusContextFactory newInstance() {
		return new GlobusContextFactory();
	}

	public GlobusContext createContext() {
		return new DefaultGlobusContext();
	}
}
