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

/**
 * Represents configuration of interceptor. Contains scoped name of
 * a interceptor.
 */
public class InterceptorConfig<T extends Interceptor> {

    private T interceptor;
    private String scope;
    

    public InterceptorConfig(String initScope, T interceptor) {
        this.interceptor = interceptor;
        this.scope = initScope;
    }
    
    public String getScope() {
        return this.scope;
    }

    public T getInterceptor() {
        return this.interceptor;
    }

    public String toString() {
        return "Interceptor: " + this.scope + ":" + this.interceptor.getClass().getCanonicalName();
    }
}
