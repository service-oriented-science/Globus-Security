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

import java.rmi.RemoteException;

/**
 * This exception is thrown if irrecoverable error occurs in PDP
 * processing. Typically the exception is treated by the combining
 * algorithm as an error that stops further processing.
 */
public class AuthorizationException extends RemoteException {

    /**
	 * 
	 */
	private static final long serialVersionUID = -4545528761577218890L;

	public AuthorizationException(String msg) {
        super(msg);
    }

    public AuthorizationException(Throwable root) {
        super("", root);
    }

    public AuthorizationException(String msg, Throwable root) {
        super(msg, root);
    }
}
