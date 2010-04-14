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

import java.io.Serializable;

/**
 * Data type containing requesting entity attributes.  Used in
 * {@link PIP#collectAttributes(RequestEntities)}
 */
public class RequestEntities implements Serializable {

    private static final long serialVersionUID = 7030614667853315588L;

    // Attributes of requesting subject
    private EntityAttributes requestor;
    // Attributes of requesting action
    private EntityAttributes action;
    // Attributes of requesting resource
    private EntityAttributes resource;
    // Attributes of environment
    private EntityAttributes environment;

    public RequestEntities() {
    }

    /**
     * @param initRequestor   EntityAttribute for requesting subject
     * @param initAction      EntityAttribute for requesting action
     * @param initResource    EntityAttribute for requesting resource
     * @param initEnvironment EntityAttribute for requesting environment
     */
    public RequestEntities(EntityAttributes initRequestor,
                           EntityAttributes initAction,
                           EntityAttributes initResource,
                           EntityAttributes initEnvironment) {

        this.requestor = initRequestor;
        this.action = initAction;
        this.resource = initResource;
        this.environment = initEnvironment;
    }

//    public void setRequestor(EntityAttributes requestor) {
//        this.requestor = requestor;
//    }
//
//    public void setAction(EntityAttributes action) {
//        this.action = action;
//    }
//
//    public void setResource(EntityAttributes resource) {
//        this.resource = resource;
//    }
//
//    public void setEnvironment(EntityAttributes environment) {
//        this.environment = environment;
//    }

    public EntityAttributes getRequestor() {
        return this.requestor;
    }
    
    @SuppressWarnings("unchecked")
	public <T extends EntityAttributes> T getRequestor(Class<T> requestorType){
    	return (T) this.requestor;
    }

    public EntityAttributes getAction() {
        return this.action;
    }
    
    @SuppressWarnings("unchecked")
	public <T extends EntityAttributes> T getAction(Class<T> actionType){
    	return (T) this.action;
    }

    public EntityAttributes getResource() {
        return this.resource;
    }
    
    @SuppressWarnings("unchecked")
	public <T extends EntityAttributes> T getResource(Class<T> resourceType){
    	return (T) this.resource;
    }

    public EntityAttributes getEnvironment() {
        return this.environment;
    }
    
    @SuppressWarnings("unchecked")
	public <T extends EntityAttributes> T getEnvironment(Class<T> environmentType){
    	return (T) this.environment;
    }
}
