package org.globus.crux.jsse;

import org.globus.security.util.SSLConfigurator;

public class SSLConfiguratorHolder extends AbstractNamedSecurityObject {
	private SSLConfigurator configurator;

	public SSLConfigurator getConfigurator() {
		return configurator;
	}

	public void setConfigurator(SSLConfigurator configurator) {
		this.configurator = configurator;
	}
}
