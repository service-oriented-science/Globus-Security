/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.globus.security.authorization.xml;

import org.globus.security.authorization.AuthorizationEngineSpi;
import org.globus.security.authorization.BootstrapPIP;
import org.globus.security.authorization.PDPInterceptor;
import org.globus.security.authorization.PIPInterceptor;

import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 26, 2010
 * Time: 1:07:59 PM
 * To change this template use File | Settings | File Templates.
 */
public class AuthZChain {
    private List<PDPInterceptor> pdps;
    private List<PIPInterceptor> pips;
    private List<BootstrapPIP> bootPips;
    private AuthorizationEngineSpi combiningAlgorithm;
    private String combiningAlg;

    public List<PDPInterceptor> getPdps() {
        return pdps;
    }

    public void setPdps(List<PDPInterceptor> pdps) {
        this.pdps = pdps;
    }

    public List<PIPInterceptor> getPips() {
        return pips;
    }

    public void setPips(List<PIPInterceptor> pips) {
        this.pips = pips;
    }

    public List<BootstrapPIP> getBootPips() {
        return bootPips;
    }

    public void setBootPips(List<BootstrapPIP> bootPips) {
        this.bootPips = bootPips;
    }

    public AuthorizationEngineSpi getCombiningAlgorithm() {
        return combiningAlgorithm;
    }

    public void setCombiningAlgorithm(AuthorizationEngineSpi combiningAlgorithm) {
        this.combiningAlgorithm = combiningAlgorithm;
    }

    public void setCombiningAlg(String combiningAlg) {
        this.combiningAlg = combiningAlg;
    }

    public String getCombiningAlg() {
        return this.combiningAlg;
    }
}
