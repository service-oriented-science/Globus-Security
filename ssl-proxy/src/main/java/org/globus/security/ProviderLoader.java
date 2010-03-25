package org.globus.security;

import java.security.Security;

import org.globus.security.provider.GlobusProvider;

public class ProviderLoader {
	private GlobusProvider provider;
	
	public ProviderLoader(){
		provider = new GlobusProvider();
		Security.addProvider(provider);
	}
	
	public GlobusProvider getProvider(){
		return provider;
	}
}
