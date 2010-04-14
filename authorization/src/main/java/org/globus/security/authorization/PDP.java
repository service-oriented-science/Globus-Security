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
 * This defines the interface an authorization scheme needs to
 * implement. AuthorizationException should be thrown only if some
 * unexpected error occured (for example in configuration). Any other
 * issues should be returned as a part of Decision object, with a deny
 * or indeterminate, as appropriate. If an AuthorizationException is
 * thrown, the framework just throws the exception and no
 * further processing is done.
 */
public interface PDP {

    Decision canAccess(RequestEntities requestEntities, NonRequestEntities nonReqEntities, AuthorizationContext context)
        throws AuthorizationException;

    Decision canAdminister(RequestEntities requestEntities, NonRequestEntities nonReqEntities, AuthorizationContext context)
        throws AuthorizationException;
}
