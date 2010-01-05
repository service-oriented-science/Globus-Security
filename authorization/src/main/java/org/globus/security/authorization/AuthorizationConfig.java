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
 * Class to hold configuration information for interceptors configured
 * as part of authorization chain.
 */
public class AuthorizationConfig {

    private InterceptorConfig[] bootstrapPips;
    private InterceptorConfig[] pips;
    private InterceptorConfig[] pdps;

    public AuthorizationConfig(InterceptorConfig[] bootstrap_,
                               InterceptorConfig[] pips_,
                               InterceptorConfig[] pdps_) {
        this.bootstrapPips = bootstrap_;
        this.pips = pips_;
        this.pdps = pdps_;
    }

    public void setBootstrapPips(InterceptorConfig[] inter) {
        this.bootstrapPips = inter;
    }

    public void setPips(InterceptorConfig[] inter) {
        this.pips = inter;
    }

    public void setPdps(InterceptorConfig[] inter) {
        this.pdps = inter;
    }

    public InterceptorConfig[] getBootstrapPips() {
        return this.bootstrapPips;
    }

    public InterceptorConfig[] getPips() {
        return this.pips;
    }

    public InterceptorConfig[] getPdps() {
        return this.pdps;
    }
}
