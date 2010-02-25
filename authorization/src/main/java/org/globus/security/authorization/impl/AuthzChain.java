package org.globus.security.authorization.impl;

import java.util.Collections;
import java.util.List;

import org.globus.security.authorization.BootstrapPIP;
import org.globus.security.authorization.PDPInterceptor;
import org.globus.security.authorization.PIPInterceptor;

public class AuthzChain {
	
	private List<BootstrapPIP> bootstrapPips;
	private List<PIPInterceptor> pips;	
	private List<PDPInterceptor> pdps;

	public void setBootstrapPips(List<BootstrapPIP> bootstrapPips) {
		this.bootstrapPips = bootstrapPips;
	}

	public void setPips(List<PIPInterceptor> pips) {
		this.pips = pips;
	}

	public void setPdps(List<PDPInterceptor> pdps) {
		this.pdps = pdps;
	}

	public List<BootstrapPIP> getBootstrapPips() {
		return Collections.unmodifiableList(bootstrapPips);
	}

	public List<PIPInterceptor> getPips() {
		return Collections.unmodifiableList(pips);
	}

	public List<PDPInterceptor> getPdps() {
		return Collections.unmodifiableList(pdps);
	}
}
