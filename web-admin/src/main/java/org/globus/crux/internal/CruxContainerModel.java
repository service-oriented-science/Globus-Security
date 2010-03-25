package org.globus.crux.internal;

import java.util.List;

import org.globus.crux.setup.ComponentFactory;

public class CruxContainerModel {

	private List<ComponentFactory<?>> pipFactories;
	private List<ComponentFactory<?>> bootStrapPipFactories;
	private List<ComponentFactory<?>> pdpFactories;
	private List<ComponentFactory<?>> authorizationEngineFactories;

	public List<ComponentFactory<?>> getPipFactories() {
		return pipFactories;
	}

	public void setPipFactories(List<ComponentFactory<?>> pipFactories) {
		this.pipFactories = pipFactories;
	}

	public List<ComponentFactory<?>> getBootStrapPipFactories() {
		return bootStrapPipFactories;
	}

	public void setBootStrapPipFactories(
			List<ComponentFactory<?>> bootStrapPipFactories) {
		this.bootStrapPipFactories = bootStrapPipFactories;
	}

	public List<ComponentFactory<?>> getPdpFactories() {
		return pdpFactories;
	}

	public void setPdpFactories(List<ComponentFactory<?>> pdpFactories) {
		this.pdpFactories = pdpFactories;
	}

	public List<ComponentFactory<?>> getAuthorizationEngineFactories() {
		return authorizationEngineFactories;
	}

	public void setAuthorizationEngineFactories(
			List<ComponentFactory<?>> authorizationEngineFactories) {
		this.authorizationEngineFactories = authorizationEngineFactories;
	}

}
