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
package org.globus.security;

import java.security.InvalidAlgorithmParameterException;

import javax.security.auth.x500.X500Principal;

/**
 * FILL ME.
 *
 * @author ranantha@mcs.anl.gov // FIXME: Maybe a provider  access to this?
 */
public abstract class SigningPolicyStore {

    /**
     * FixMe: Add documentation
     *
     * @param parameters FixMe document me.
     * @throws InvalidAlgorithmParameterException FixMe document me.
     */
    public SigningPolicyStore(final SigningPolicyStoreParameters parameters)
            throws InvalidAlgorithmParameterException {

    }

    /**
     * FixMe: Document me
     *
     * @param caPrincipal Document Me.
     * @return Document Me.
     * @throws SigningPolicyStoreException Document Me.
     */
    public abstract SigningPolicy getSigningPolicy(X500Principal caPrincipal)
            throws SigningPolicyStoreException;
}
