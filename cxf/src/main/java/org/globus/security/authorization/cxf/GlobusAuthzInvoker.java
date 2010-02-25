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

import org.apache.cxf.message.Exchange;
import org.apache.cxf.service.invoker.Invoker;
import org.globus.security.authorization.jaas.GlobusSubject;

import javax.security.auth.Subject;
import java.security.PrivilegedAction;

/**
 * This is a very simple invoker which just adds the Globus identity information to JAAS as part of the service
 * invocation process.
 *
 * @since 1.0
 * @version 1.0
 */
public class GlobusAuthzInvoker implements Invoker {
    private Invoker invoker;

    public GlobusAuthzInvoker(Invoker invoker) {
        this.invoker = invoker;
    }

    /**
     * Invoke the service using the security credentials of the caller.
     *
     * @param exchange The request to execute.
     * @param o The parameters passed
     * @return The result of the method call. 
     */
    public Object invoke(final Exchange exchange, final Object o) {
        PrivilegedAction<Object> action = new PrivilegedAction<Object>() {
            public Object run() {
                return invoker.invoke(exchange, o);
            }
        };
        Subject subject = exchange.get(Subject.class);
        if (subject != null) {
            return GlobusSubject.doAs(subject, action);
        } else {
            return invoker.invoke(exchange, o);
        }
    }    
}
