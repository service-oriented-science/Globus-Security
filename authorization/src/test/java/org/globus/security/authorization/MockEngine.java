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
package org.globus.security.authorization;

import org.globus.security.authorization.providers.AbstractEngine;

import java.util.List;

public class MockEngine extends AbstractEngine {

    public MockEngine(String chainName) {
        super(chainName);
    }
       
    public String getAlgorithm() {
    	return "Mock";
    }



	public Decision engineAuthorize(RequestEntities reqAttribute, EntityAttributes resourceOwner)
            throws AuthorizationException {

        collectAttributes(reqAttribute);
        return null;
    }

    public List engineGetSubjectAttrList() {
        return this.getNonReqEntities().getSubjectAttrsList();
    }

    public List engineGetActionAttrList() {
        return this.getNonReqEntities().getActionAttrsList();
    }

    public List engineGetResourceAttrList() {
        return this.getNonReqEntities().getResourceAttrsList();
    }

    public List<? extends PDPInterceptor> getPDPs() {
        return this.getPdps();
    }

    public List<? extends PIPInterceptor> getPIPs() {
        return this.getPips();
    }

    public List<? extends BootstrapPIP> getBootstrapPIPs() {
        return this.getBootstrapPips();
    }
}
