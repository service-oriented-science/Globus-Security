/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.security.authorization;

/**
 * Class to hold configuration information for interceptors configured as part
 * of authorization chain.
 */
@SuppressWarnings("unchecked")
public class AuthorizationConfig {

	private InterceptorConfig<BootstrapPIP>[] bootstrapPips;
	private InterceptorConfig<PIPInterceptor>[] pips;
	private InterceptorConfig<PDPInterceptor>[] pdps;

	public AuthorizationConfig(InterceptorConfig<BootstrapPIP>[] initBootstrap,
			InterceptorConfig<PIPInterceptor>[] initPips, InterceptorConfig<PDPInterceptor>[] initPdps) {
		setBootstrapPips(initBootstrap);
		setPips(initPips);
		setPdps(initPdps);
	}

	public void setBootstrapPips(InterceptorConfig<BootstrapPIP>[] inter) {
		if (inter != null) {
			this.bootstrapPips = new InterceptorConfig[inter.length];
			System.arraycopy(inter, 0, this.bootstrapPips, 0, inter.length);
		}
	}

	public void setPips(InterceptorConfig<PIPInterceptor>[] inter) {
		if (inter != null) {
			this.pips = new InterceptorConfig[inter.length];
			System.arraycopy(inter, 0, this.pips, 0, inter.length);
		}
	}

	public void setPdps(InterceptorConfig<PDPInterceptor>[] inter) {
		if (inter != null) {
			this.pdps = new InterceptorConfig[inter.length];
			System.arraycopy(inter, 0, this.pdps, 0, inter.length);
		}
	}

	public InterceptorConfig<BootstrapPIP>[] getBootstrapPips() {
		InterceptorConfig<BootstrapPIP>[] toReturn = null;
		if (this.bootstrapPips != null) {
			toReturn = new InterceptorConfig[this.bootstrapPips.length];
			System.arraycopy(this.bootstrapPips, 0, toReturn, 0, this.bootstrapPips.length);
		}
		return toReturn;
	}

	public InterceptorConfig<PIPInterceptor>[] getPips() {
		InterceptorConfig<PIPInterceptor>[] toReturn = null;
		if (this.pips != null) {
			toReturn = new InterceptorConfig[this.pips.length];
			System.arraycopy(this.pips, 0, toReturn, 0, this.pips.length);
		}
		return toReturn;
	}

	public InterceptorConfig<PDPInterceptor>[] getPdps() {
		InterceptorConfig<PDPInterceptor>[] toReturn = null;
		if (this.pdps != null) {
			toReturn = new InterceptorConfig[this.pdps.length];
			System.arraycopy(this.pdps, 0, toReturn, 0, this.pdps.length);
		}
		return toReturn;
	}
}
