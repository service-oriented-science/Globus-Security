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

import java.util.HashMap;

public class MockChainConfig implements ChainConfig {

    private HashMap properties;

    public MockChainConfig() {
        this(null);
    }

    public MockChainConfig(HashMap properties_) {
        this.properties = properties_;
        if (this.properties == null) {
            this.properties = new HashMap();
        }
    }

    /**
     * Returns value of property identified by <i>name-property</i>
     *
     * @param name     scope of the property
     * @param property name of the property
     */
    public Object getProperty(String name, String property) {
        return this.properties.get(name + "-" + property);
    }

    /**
     * Sets the value of property identified by <i>name-property</i>
     *
     * @param name     scope of the property
     * @param property name of the property
     * @param obj      Value of the property
     */
    public void setProperty(String name, String property, Object obj) {
        this.properties.put(name + "-" + property, obj);
    }
}

