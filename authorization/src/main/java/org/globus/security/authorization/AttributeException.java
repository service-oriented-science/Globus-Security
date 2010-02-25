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
 * Exception is thrown when an error occurs in in AttributeBase Collection
 * Framework.
 */
public class AttributeException extends AuthorizationException {

    /**
	 * 
	 */
	private static final long serialVersionUID = -4011960739423391652L;

	public AttributeException(String message) {
        super(message);
    }

    public AttributeException(Exception cause) {
        super(null, cause);
    }

    public AttributeException(String message, Exception cause) {
        super(message, cause);
    }
}
