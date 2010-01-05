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

import java.net.URI;

public class TestConstants {

    public static URI ISSUER_ID = null;
    public static URI STRING_DATATYPE_URI = null;

    static {
        try {
            ISSUER_ID = new URI("http://www.globus.org/test/id");
            STRING_DATATYPE_URI =
                    new URI("http://www.w3.org/2001/XMLSchema#string");
        } catch (Exception exp) {
            throw new RuntimeException(exp.getMessage());
        }
    }
}
