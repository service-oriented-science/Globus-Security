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

public class MockBootstrapPIP implements BootstrapPIP {

    private int initCount = 0;

    public void initialize(String chainName, String prefix_,
                           ChainConfig config) throws InitializeException {

        initCount++;
    }

    public void collectRequestAttributes(RequestEntities requestAttr)
            throws AttributeException {
    }

    public NonRequestEntities collectAttributes(RequestEntities requestAttr)
            throws AttributeException {
        return null;
    }

    public int getInitializationCount() {
        return initCount;
    }

    public void close() {
    }
}
