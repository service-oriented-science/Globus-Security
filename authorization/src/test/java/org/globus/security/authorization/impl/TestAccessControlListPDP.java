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
import java.util.Vector;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.globus.security.authorization.Attribute;
import org.globus.security.authorization.Decision;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.IdentityAttributeCollection;
import org.globus.security.authorization.RequestEntities;
import org.globus.security.authorization.util.AttributeUtil;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * FILL ME
 * 
 * @author ranantha@mcs.anl.gov
 */
public class TestAccessControlListPDP {

	// Entity A
	static Principal entityA1 = new X500Principal("CN=EA1, OU=bar, O=foo");
	static Principal entityA2 = new X500Principal("CN=EA2, OU=bar, O=foo");
	// Entity B
	static Principal entityB1 = new X500Principal("CN=EB1, OU=bar, O=foo");
	// Entity C
	static Principal entityC1 = new X500Principal("CN=EC1, OU=bar, O=foo");
	static Principal entityC2 = new X500Principal("CN=EC2, OU=bar, O=foo");

	// ACL has entity A for access and admin
	static Vector<Principal> test1 = new Vector<Principal>(1);
	// ACL has entity A and entity B for access and entity C for admin
	static Vector<Principal> test2Access = new Vector<Principal>(2);
	static Vector<Principal> test2Admin = new Vector<Principal>(1);

	static Subject entityA;
	static Subject entityB;
	static Subject entityC;
	static Subject entityAnon;

	// ACL has anonymous and entity A allowed for access, anonymous and entity B
	// for admin

	@BeforeClass
	public static void setup() {

		test1.add(entityA2);

		test2Access.add(entityA1);
		test2Access.add(entityB1);
		test2Admin.add(entityC2);

		entityA = new Subject();
		entityA.getPrincipals().add(entityA1);
		entityA.getPrincipals().add(entityA2);

		entityB = new Subject();
		entityB.getPrincipals().add(entityB1);

		entityC = new Subject();
		entityC.getPrincipals().add(entityC1);
		entityC.getPrincipals().add(entityC2);

		entityAnon = new Subject();
	}

	@Test
	public void test1() throws Exception {

		// Access and admin rights allowed for permitted.
		AccessControlListPDP pdp = new AccessControlListPDP(test1);
		RequestEntities request = getRequestor(entityA);
		Decision decision = pdp.canAccess(request, null);
		assert (decision.isPermit());

		decision = pdp.canAdminister(getRequestor(entityA), null);
		assert (decision.isPermit());

		decision = pdp.canAccess(getRequestor(entityB), null);
		assert (decision.isDeny());

		decision = pdp.canAdminister(getRequestor(entityB), null);
		assert (decision.isDeny());

		decision = pdp.canAccess(getRequestor(entityAnon), null);
		assert (decision.isDeny());

		decision = pdp.canAdminister(getRequestor(entityAnon), null);
		assert (decision.isDeny());

	}

	@SuppressWarnings("unchecked")
	private RequestEntities getRequestor(Subject subject) {

		IdentityAttributeCollection idenAttrColl = new IdentityAttributeCollection();
		Attribute subjectAttribute = new Attribute(AttributeUtil.getPeerSubjectAttrIdentifier(), null, Calendar
				.getInstance(), null);
		subjectAttribute.addAttributeValue(subject);
		idenAttrColl.add(subjectAttribute);

		EntityAttributes attribute = new EntityAttributes(idenAttrColl);

		RequestEntities entity = new RequestEntities(attribute, null, null, null);

		return entity;
	}
}
