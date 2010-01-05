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
 * Interface for authorization engines.
 */
public interface AuthorizationEngineSpi extends Serializable {

    /**
     * Initializes the engine with interceptor information and
     * parameters. The engine should initialize all configured
     * interceptors
     *
     * @param chainName   Name for authorization chain
     * @param authzConfig Configuration of interceptors in authorization chain
     * @param chainConfig Parameters for interceptors to use.
     */
    public void engineInitialize(String chainName,
                                 AuthorizationConfig authzConfig,
                                 ChainConfig chainConfig)
            throws InitializeException;

    /**
     * Evalauates the authorization chain to determine of the subject
     * is allowed to perfrorm the action on the resource. Subject, action
     * and resource are specified in the RequestEntities object.
     *
     * @param reqAttribute  Object initialized with information about the request
     *                      context.
     * @param resourceOwner Resource owner entity.
     */
    public Decision engineAuthorize(RequestEntities reqAttribute,
                                    EntityAttributes resourceOwner)
            throws AuthorizationException;

    /**
     * The engine should invoke close on all interceptors
     */
    public void engineClose() throws CloseException;


    /**
     * Returns the parameters used by interceprors.
     */
    public ChainConfig getChainConfig();
}