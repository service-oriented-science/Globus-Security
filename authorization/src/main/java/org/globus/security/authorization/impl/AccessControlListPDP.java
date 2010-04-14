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

import java.security.Principal;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.globus.security.authorization.Attribute;
import org.globus.security.authorization.AttributeIdentifier;
import org.globus.security.authorization.AuthorizationException;
import org.globus.security.authorization.Decision;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.AuthorizationContext;
import org.globus.security.authorization.IdentityAttributeCollection;
import org.globus.security.authorization.NonRequestEntities;
import org.globus.security.authorization.PDP;
import org.globus.security.authorization.RequestEntities;
import org.globus.security.authorization.util.AttributeUtil;

/**
 * This PDP takes a list of accepted principals, one for access to the resource
 * and another to the administrative resource. If at-least one of the request
 * entities' Principal is in the provided ACL, a permit decision is returned.
 * The PDP can also be configured to accept anonymous clients, in which case, if
 * a request subject with no Principals is presented, the client is permitted.
 * By default, anonymous clients are denied.
 * 
 * @author ranantha@mcs.anl.gov
 */
public class AccessControlListPDP implements PDP {

	private Collection<Principal> accessAcl;
	private Collection<Principal> adminAcl;
	private boolean anonymousAllowed;

	/**
	 * Constructor.
	 * 
	 * @param aclParameter
	 *            Collection of Principals that are allowed access and
	 *            administrative rights.
	 */
	public AccessControlListPDP(Collection<Principal> aclParameter) {

		this(aclParameter, aclParameter, false);
	}

	/**
	 * Constructor
	 * 
	 * @param accessAclParam
	 *            Collection of Principals that are allowed access rights.
	 * @param adminAclParam
	 *            Collection of Principals that are allowed administrative
	 *            rights.
	 */
	public AccessControlListPDP(Collection<Principal> accessAclParam, Collection<Principal> adminAclParam) {
		this(accessAclParam, adminAclParam, false);
	}

	/**
	 * Constructor
	 * 
	 * @param accessAclParam
	 *            Collection of Principals that are allowed access rights.
	 * @param adminAclParam
	 *            Collection of Principals that are allowed administrative
	 *            rights.
	 * @param anonymousAllowedParam
	 *            If set to true, anonymous clients are permitted access. If set
	 *            to false, anonymous clients are denied.
	 */
	public AccessControlListPDP(Collection<Principal> accessAclParam, Collection<Principal> adminAclParam,
			boolean anonymousAllowedParam) {

		if ((accessAclParam == null) || (adminAclParam == null)) {
			throw new IllegalArgumentException("Access Control List cannot be null");
		}

		if ((accessAclParam.size() == 0 || adminAclParam.size() == 0)) {
			throw new IllegalArgumentException("Access Control List cannot be empty");

		}

		this.accessAcl = accessAclParam;
		this.adminAcl = adminAclParam;
		this.anonymousAllowed = anonymousAllowedParam;
	}

	/**
	 * Decision on whether request entity is allowed access to the resource.
	 * 
	 * @param requestEntities
	 * @param nonReqEntities
	 * @return
	 * @throws AuthorizationException
	 */
	public Decision canAccess(RequestEntities requestEntities, NonRequestEntities nonReqEntities, AuthorizationContext context)
			throws AuthorizationException {

		return getDecision(requestEntities, this.accessAcl, context);
	}

	/**
	 * Decision on whether request entity is allowed administrative access to
	 * the resource.
	 * 
	 * @param requestEntities
	 * @param nonReqEntities
	 * @return
	 * @throws AuthorizationException
	 */
	public Decision canAdminister(RequestEntities requestEntities, NonRequestEntities nonReqEntities, AuthorizationContext context)
			throws AuthorizationException {

		return getDecision(requestEntities, this.adminAcl, context);
	}

	private Set getAttributeValue(Collection<Attribute<?>> attributes) {

		if (attributes == null) {
			return null;
		}

		Set valueSet = new HashSet();
		Iterator<Attribute<?>> attributesIterator = attributes.iterator();
		while (attributesIterator.hasNext()) {
			Attribute attribute = attributesIterator.next();
			Set<Set> attributeValues = attribute.getAttributeValueSet();
			valueSet.addAll(attributeValues);
		}

		return valueSet;
	}

	private boolean isPermit(Collection<Principal> acl, Set<Principal> requestPrincipal) {

		if (requestPrincipal == null) {
			return false;
		}

		if (requestPrincipal.size() < 1) {
			if (this.anonymousAllowed) {
				return true;
			} else {
				return false;
			}
		}

		Iterator<Principal> iterator = requestPrincipal.iterator();
		while (iterator.hasNext()) {
			Principal principal = iterator.next();
			if (acl.contains(principal)) {
				return true;
			}
		}

		return false;
	}

	private Decision getDecision(RequestEntities requestEntities, Collection<Principal> acl, AuthorizationContext context) {

		EntityAttributes requestor = requestEntities.getRequestor();

		if (requestor != null) {
			AttributeIdentifier identifier = AttributeUtil.getPrincipalIdentifier();
			IdentityAttributeCollection identityAttributes = requestor.getIdentityAttributes();
			Collection<Attribute<?>> principals = identityAttributes.getAttributes(identifier);
			Set<Set> principalValues = getAttributeValue(principals);
			if (principalValues != null) {
				Iterator<Set> principalValuesIterator = principalValues.iterator();
				while (principalValuesIterator.hasNext()) {
					if (isPermit(acl, principalValuesIterator.next())) {
						Decision decision = new Decision(context.getContainerEntity(), requestEntities.getRequestor(),
								Decision.PERMIT, Calendar.getInstance(), null);
						return decision;
					}
				}
			}
		}

		Decision decision = new Decision(context.getContainerEntity(), requestEntities.getRequestor(), Decision.DENY,
				Calendar.getInstance(), null);
		return decision;
	}
}
