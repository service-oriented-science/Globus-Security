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
 * Interface for maintaining parameters required by interceptors in an
 * authorization chain. Each property is identified by a scoped name
 * and the value can be any Java object
 */
public interface ChainConfig extends Serializable {

    Object getProperty(String prefix, String property);

    void setProperty(String prefix, String property, Object value);
}
