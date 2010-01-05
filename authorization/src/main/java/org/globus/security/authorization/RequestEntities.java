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

    // Attributes of requesting subject
    private EntityAttributes requestor = null;
    // Attributes of requesting action
    private EntityAttributes action = null;
    // Attributes of requesting resource
    private EntityAttributes resource = null;
    // Attributes of environment
    private EntityAttributes environment = null;

    public RequestEntities() {
    }

    /**
     * @param requestor_   EntityAttribute for requesting subject
     * @param action_      EntityAttribute for requesting action
     * @param resource_    EntityAttribute for requesting resource
     * @param environment_ EntityAttribute for requesting environment
     */
    public RequestEntities(EntityAttributes requestor_,
                           EntityAttributes action_,
                           EntityAttributes resource_,
                           EntityAttributes environment_) {

        this.requestor = requestor_;
        this.action = action_;
        this.resource = resource_;
        this.environment = environment_;
    }

    public void setRequestor(EntityAttributes requestor_) {
        this.requestor = requestor_;
    }

    public void setAction(EntityAttributes action_) {
        this.action = action_;
    }

    public void setResource(EntityAttributes resource_) {
        this.resource = resource_;
    }

    public void setEnvironment(EntityAttributes environment_) {
        this.environment = environment_;
    }

    public EntityAttributes getRequestor() {
        return this.requestor;
    }

    public EntityAttributes getAction() {
        return this.action;
    }

    public EntityAttributes getResource() {
        return this.resource;
    }

    public EntityAttributes getEnvironment() {
        return this.environment;
    }
}
