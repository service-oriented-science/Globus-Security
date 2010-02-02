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

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 26, 2010
 * Time: 1:11:46 PM
 * To change this template use File | Settings | File Templates.
 */
public class SecurityDescriptor {
    private AuthZChain adminAuthzChain;
    private AuthZChain authzChain;


    public AuthZChain getAdminAuthzChain() {
        return adminAuthzChain;
    }

    public void setAdminAuthzChain(AuthZChain adminAuthzChain) {
        this.adminAuthzChain = adminAuthzChain;
    }

    public AuthZChain getAuthzChain() {
        return authzChain;
    }

    public void setAuthzChain(AuthZChain authzChain) {
        this.authzChain = authzChain;
    }
}
