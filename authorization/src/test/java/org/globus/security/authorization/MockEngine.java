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

import java.util.List;

import org.globus.security.authorization.providers.AbstractEngine;

public class MockEngine extends AbstractEngine {

    public Decision engineAuthorize(RequestEntities reqAttribute,
                                    EntityAttributes resourceOwner)
            throws AuthorizationException {

        collectAttributes(reqAttribute);
        return null;
    }

    public List engineGetSubjectAttrList() {
        return this.nonReqEntities.getSubjectAttrsList();
    }

    public List engineGetActionAttrList() {
        return this.nonReqEntities.getActionAttrsList();
    }

    public List engineGetResourceAttrList() {
        return this.nonReqEntities.getResourceAttrsList();
    }

    public PDPInterceptor[] getPDPs() {
        return this.pdps;
    }

    public PIPInterceptor[] getPIPs() {
        return this.pips;
    }

    public BootstrapPIP[] getBootstrapPIPs() {
        return this.bootstrapPips;
    }
}
