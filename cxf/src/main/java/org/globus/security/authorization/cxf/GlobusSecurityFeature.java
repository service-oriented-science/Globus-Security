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

package org.globus.security.authorization.cxf;

import java.util.Map;
import java.util.UUID;

import org.apache.cxf.Bus;
import org.apache.cxf.endpoint.Server;
import org.apache.cxf.feature.AbstractFeature;
import org.apache.cxf.service.Service;

/**
 * This feature adds the Globus Security interceptors and invokers to this service.
 *
 * @since 1.0
 * @version 1.0
 */
public class GlobusSecurityFeature extends AbstractFeature {

    /**
     * Setup invoker and interceptors required for Globus Security
     *
     * @param server The server we are configuring.
     * @param bus The bus on which the server is running.
     */
    @Override
    public void initialize(Server server, Bus bus) {
        Service service = server.getEndpoint().getService();
        service.getInInterceptors().add(new ContainerIdentityExtractor());
        service.setInvoker(new GlobusAuthzInvoker(service.getInvoker()));
        Map<String, Object> busProperties = bus.getProperties(); 
        String globusId = (String) busProperties.get("GLOBUS_CONTAINER_ID");
        if(globusId == null){
        	busProperties.put("GLOBUS_CONTAINER_ID", UUID.randomUUID().toString());
        }
    }
}
