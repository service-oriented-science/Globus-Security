package org.globus.crux.jsse;


public class SSLConfiguratorHolder extends AbstractNamedSecurityObject {
	private SSLConfigurator configurator;

	public SSLConfigurator getConfigurator() {
		return configurator;
	}

	public void setConfigurator(SSLConfigurator configurator) {
		this.configurator = configurator;
	}
}
