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
package org.globus.security.authorization.impl;

import java.util.Calendar;
import java.util.Set;

import javax.security.auth.Subject;

import org.globus.security.authorization.Attribute;
import org.globus.security.authorization.AttributeException;
import org.globus.security.authorization.AttributeIdentifier;
import org.globus.security.authorization.BootstrapPIP;
import org.globus.security.authorization.CloseException;
import org.globus.security.authorization.EntitiesContainer;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.AuthorizationContext;
import org.globus.security.authorization.IdentityAttributeCollection;
import org.globus.security.authorization.RequestEntities;
import org.globus.security.authorization.util.AttributeUtil;

public class X509BootstrapPIP implements BootstrapPIP {

	private static final long serialVersionUID = 4102147324580817900L;

	@SuppressWarnings("unchecked")
	public RequestEntities collectRequestAttributes(RequestEntities requestAttrs, AuthorizationContext context)
			throws AttributeException {

		EntityAttributes containerEntity = context.getContainerEntity();

		Subject peerSubject = context.getPeerSubject();
		if (peerSubject != null) {
			IdentityAttributeCollection idenAttrColl = new IdentityAttributeCollection();
			Attribute subjectAttribute = new Attribute(AttributeUtil.getPeerSubjectAttrIdentifier(), containerEntity,
					Calendar.getInstance(), null);
			subjectAttribute.addAttributeValue(peerSubject);
			idenAttrColl.add(subjectAttribute);

			Set peerPrincipals = peerSubject.getPrincipals();
			if (peerPrincipals.size() > 0) {
				AttributeIdentifier identifier = AttributeUtil.getPrincipalIdentifier();
				Attribute principalAttribute = new Attribute(identifier, containerEntity, Calendar.getInstance(), null,
						peerPrincipals);
				idenAttrColl.add(principalAttribute);
			}

			EntityAttributes coll = requestAttrs.getRequestor();
			if (coll == null) {
				coll = new EntityAttributes(idenAttrColl);
			} else {
				coll.addIdentityAttributes(idenAttrColl);
			}
			return new RequestEntities(coll, requestAttrs.getAction(), requestAttrs.getResource(), requestAttrs
					.getEnvironment());
		}
		return new RequestEntities(requestAttrs.getRequestor(), requestAttrs.getAction(), requestAttrs.getRequestor(),
				requestAttrs.getEnvironment());
	}

	public EntitiesContainer collectAttributes(RequestEntities requestAttr, AuthorizationContext context) {
		return null;
	}

	public void close() throws CloseException {
	}
}
