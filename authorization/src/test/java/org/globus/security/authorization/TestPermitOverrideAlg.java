/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
package org.globus.security.authorization;

import org.globus.security.authorization.providers.PermitOverrideAlg;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class TestPermitOverrideAlg {

	AttributeIdentifier attrIden = null;
	IdentityAttributeCollection resourceOwnerAttrs = null;

	@Test
	public void test() throws Exception {

		this.attrIden = MockPDPImpl.getTestUserAttrIdentifier();

		// Requestor userA
		Attribute attr = new Attribute(this.attrIden, null, Calendar.getInstance(), null);
		attr.addAttributeValue("UserA");
		IdentityAttributeCollection coll = new IdentityAttributeCollection();
		coll.add(attr);
		EntityAttributes requestor = new EntityAttributes(coll);
		RequestEntities reqAttr = new RequestEntities(requestor, null, null, null);

		// resource owner

		AttributeIdentifier attrIden = MockPDPImpl.getTestUserAttrIdentifier();
		Attribute ownerAttr = new Attribute(attrIden, null, Calendar.getInstance(), null);
		IdentityAttributeCollection attrCol = new IdentityAttributeCollection();
		attrCol.add(ownerAttr);
		EntityAttributes owner = new EntityAttributes(attrCol);

		Attribute resourceOwnerAttr = new Attribute(attrIden, owner, Calendar.getInstance(), null);

		this.resourceOwnerAttrs = new IdentityAttributeCollection();
		this.resourceOwnerAttrs.add(resourceOwnerAttr);

		scenario1Test(reqAttr);
		scenario2Test(reqAttr);
		scenario3Test(reqAttr);
		scenario4Test(reqAttr);
		scenario5Test(reqAttr);
	}

	// PDP0: resourceOwner says UserB can adminList
	// PDP1: UserB says UserA can access
	public void scenario1Test(RequestEntities reqAttr) throws Exception {

		List<PDPInterceptor> pdps = new ArrayList<PDPInterceptor>();
		PermitOverrideAlg engine = new PermitOverrideAlg("test chain");
		MockPDPImpl p0 = new MockPDPImpl();
		p0.setIssuer("container");
		p0.setAdmin(Arrays.asList("UserB"));
		p0.setOwner(this.resourceOwnerAttrs);
		pdps.add(p0);

		MockPDPImpl p1 = new MockPDPImpl();
		p1.setIssuer("UserB");
		p1.setAccess(Arrays.asList("UserA"));
		p1.setOwner(this.resourceOwnerAttrs);
		pdps.add(p1);

		engine.setPDPInterceptors(pdps);

		// Try to get decision
		Decision decision = engine.engineAuthorize(reqAttr, new EntityAttributes(this.resourceOwnerAttrs), null);
		assert (decision != null);
		assert (decision.isPermit());
		EntityAttributes retEntity = decision.getIssuer();
		assert (retEntity != null);
		assert (retEntity.getIdentityAttributes() != null);
		IdentityAttributeCollection idenCol = retEntity.getIdentityAttributes();
		assert (idenCol != null);
		assert (idenCol.isSameEntity(this.resourceOwnerAttrs));
	}

	// Use of deniedList list
	// PDP0: container says UserB can adminList
	// PDP1: UserB says UserD can adminList
	// PDP2: USerC says UserE can adminList
	// PDP3: UserE says UserA can access
	// PDP4: USerF says UserA can access
	// PDP5: UserD says UserF can adminList
	public void scenario2Test(RequestEntities reqAttr) throws Exception {

		PermitOverrideAlg engine = new PermitOverrideAlg("test chain");
		List<PDPInterceptor> pdps = new ArrayList<PDPInterceptor>();
		MockPDPImpl p0 = new MockPDPImpl();
		pdps.add(p0);
		MockPDPImpl p1 = new MockPDPImpl();
		pdps.add(p1);
		MockPDPImpl p2 = new MockPDPImpl();
		pdps.add(p2);
		MockPDPImpl p3 = new MockPDPImpl();
		pdps.add(p3);
		MockPDPImpl p4 = new MockPDPImpl();
		pdps.add(p4);
		MockPDPImpl p5 = new MockPDPImpl();
		pdps.add(p5);

		p0.setIssuer(MockPDPImpl.OWNER);
		p0.setAdmin(Arrays.asList("UserB"));
		p0.setOwner(this.resourceOwnerAttrs);
		p0.initialize();

		p1.setIssuer("UserB");
		p1.setAdmin(Arrays.asList("UserD"));
		p1.setOwner(this.resourceOwnerAttrs);
		p1.initialize();
		
		p2.setIssuer("UserC");
		p2.setAdmin(Arrays.asList("UserE"));
		p2.setOwner(this.resourceOwnerAttrs);
		p2.initialize();
		
		p3.setIssuer("UserE");
		p3.setAccess(Arrays.asList("UserA"));
		p3.setOwner(this.resourceOwnerAttrs);
		p3.initialize();
		
		p4.setIssuer("UserF");
		p4.setAccess(Arrays.asList("UserA"));
		p4.setOwner(this.resourceOwnerAttrs);
		p4.initialize();
		
		p5.setIssuer("UserD");
		p5.setAdmin(Arrays.asList("UserF"));
		p5.setOwner(this.resourceOwnerAttrs);
		p5.initialize();
		
		engine.setPDPInterceptors(pdps);

		// Try to get decision
		Decision decision = engine.engineAuthorize(reqAttr, new EntityAttributes(this.resourceOwnerAttrs), null);
		assert (decision != null);
		assert (decision.isPermit());
		EntityAttributes retEntity = decision.getIssuer();
		assert (retEntity != null);
		assert (retEntity.getIdentityAttributes() != null);
		IdentityAttributeCollection idenCol = retEntity.getIdentityAttributes();
		assert (idenCol != null);
		assert (idenCol.isSameEntity(this.resourceOwnerAttrs));

		// deny if UserD does not grant rights on UserF
		engine = new PermitOverrideAlg("testChain");
		p5.setAdmin(Arrays.asList("UserG"));		
		pdps = new ArrayList<PDPInterceptor>();
		pdps.add(p0);
		pdps.add(p1);
		pdps.add(p2);
		pdps.add(p3);
		pdps.add(p4);
		pdps.add(p5);
		engine.setPDPInterceptors(pdps);
		decision = engine.engineAuthorize(reqAttr, new EntityAttributes(this.resourceOwnerAttrs), null);
		assert (decision != null);
		assert (decision.isDeny());

	}

	// (Scenario 3) Resource owner in middle of chain (and deniedList list used)
	// PDP0: container says UserB can acess
	// PDP1: UserC says UserE can adminList
	// PDP2: UserE says UserA can access
	// PDP3: container says UserD can adminList
	// PDP4: USerF says UserA can access
	// PDP5: UserD says UserF can adminList (take this off to see no chain
	// and deny)
	public void scenario3Test(RequestEntities reqAttr) throws Exception {

		PermitOverrideAlg engine = new PermitOverrideAlg("test chain");

		ChainConfig chainConfig = new MockChainConfig();
		List<PDPInterceptor> pdps = new ArrayList<PDPInterceptor>();
		MockPDPImpl p0 = new MockPDPImpl();
		p0.setIssuer("container");
		p0.setAccess(Arrays.asList("UserB"));
		p0.setOwner(this.resourceOwnerAttrs);
		pdps.add(p0);

		MockPDPImpl p1 = new MockPDPImpl();
		p1.setIssuer("UserC");
		p1.setAdmin(Arrays.asList("UserE"));
		p1.setOwner(this.resourceOwnerAttrs);
		pdps.add(p1);

		MockPDPImpl p2 = new MockPDPImpl();
		p2.setIssuer("UserE");
		p2.setAccess(Arrays.asList("UserA"));
		p2.setOwner(this.resourceOwnerAttrs);
		pdps.add(p2);

		MockPDPImpl p3 = new MockPDPImpl();
		p3.setIssuer("container");
		p3.setAdmin(Arrays.asList("UserD"));
		p3.setOwner(this.resourceOwnerAttrs);
		pdps.add(p3);

		MockPDPImpl p4 = new MockPDPImpl();
		p4.setIssuer("UserF");
		p4.setAccess(Arrays.asList("UserA"));
		p4.setOwner(this.resourceOwnerAttrs);
		pdps.add(p4);

		chainConfig.setProperty("p5", "issuer", "UserD");
		chainConfig.setProperty("p5", "adminList", "UserF");
		chainConfig.setProperty("p6", MockPDPImpl.OWNER, this.resourceOwnerAttrs);

		MockPDPImpl p5 = new MockPDPImpl();
		p5.setIssuer("UserD");
		p5.setAdmin(Arrays.asList("UserF"));
		p5.setOwner(this.resourceOwnerAttrs);
		pdps.add(p5);

		engine.setPDPInterceptors(pdps);

		// Try to get decision
		Decision decision = engine.engineAuthorize(reqAttr, new EntityAttributes(this.resourceOwnerAttrs), null);
		assert (decision != null);
		assert (decision.isPermit());
		EntityAttributes retEntity = decision.getIssuer();
		assert (retEntity != null);
		assert (retEntity.getIdentityAttributes() != null);
		IdentityAttributeCollection idenCol = retEntity.getIdentityAttributes();
		assert (idenCol != null);
		assert (idenCol.isSameEntity(this.resourceOwnerAttrs));
	}

	// (Scenario 4) Ensure right question (adminList or access) is asked
	// at correct points
	// PDP0: container says UserD can adminList
	// says UserB can access
	// PDP1: UserF says UserA can access
	// PDP2: UserB says UserE can adminList
	// PDP3: UserC says UserG can adminList
	// PDP4: UserD says UserC can adminList
	// says UserF can access
	// PDP5: UserE says UserF can adminList
	// PDP6: UserG says UserF, UserA can adminList
	// a) container->UserD->UserC->UserG->UserF->UserA
	// b) container->UserD->UserC->UserG-> but UserG says UserA can adminList
	// not access
	// c) UserB->UserE->UserF->UserA, but container says UserB can
	// access, not adminList
	public void scenario4Test(RequestEntities reqAttr) throws Exception {
		PermitOverrideAlg engine = new PermitOverrideAlg("test chain");

		List<PDPInterceptor> pdps = new ArrayList<PDPInterceptor>();
		MockPDPImpl p0 = new MockPDPImpl();
		pdps.add(p0);
		MockPDPImpl p1 = new MockPDPImpl();
		pdps.add(p1);
		MockPDPImpl p2 = new MockPDPImpl();
		pdps.add(p2);
		MockPDPImpl p3 = new MockPDPImpl();
		pdps.add(p3);
		MockPDPImpl p4 = new MockPDPImpl();
		pdps.add(p4);
		MockPDPImpl p5 = new MockPDPImpl();
		pdps.add(p5);
		MockPDPImpl p6 = new MockPDPImpl();
		pdps.add(p6);

		p0.setIssuer("container");
		p0.setAdmin(Arrays.asList("UserD"));
		p0.setAccess(Arrays.asList("UserB"));
		p0.setOwner(this.resourceOwnerAttrs);

		p1.setIssuer("UserF");
		p1.setAccess(Arrays.asList("UserA"));
		p1.setOwner(this.resourceOwnerAttrs);

		p2.setIssuer("UserB");
		p2.setAdmin(Arrays.asList("UserE"));
		p2.setOwner(this.resourceOwnerAttrs);

		p3.setIssuer("UserC");
		p3.setAdmin(Arrays.asList("UserG"));
		p3.setOwner(this.resourceOwnerAttrs);

		p4.setIssuer("UserD");
		p4.setAccess(Arrays.asList("UserF"));
		p4.setAdmin(Arrays.asList("UserC"));
		p4.setOwner(this.resourceOwnerAttrs);

		p5.setIssuer("UserE");
		p5.setAdmin(Arrays.asList("UserF"));
		p5.setOwner(this.resourceOwnerAttrs);

		p6.setIssuer("UserG");
		p6.setAdmin(Arrays.asList("UserF", "UserA"));
		p5.setOwner(this.resourceOwnerAttrs);

		engine.setPDPInterceptors(pdps);

		// Try to get decision
		Decision decision = engine.engineAuthorize(reqAttr, new EntityAttributes(this.resourceOwnerAttrs), null);
		assert (decision != null);
		assert (decision.isPermit());

		// scenario 4(b)
		engine = new PermitOverrideAlg("test chain");
		pdps = new ArrayList<PDPInterceptor>();
		// Disable current premit chain: PDP6: UserG says UserA can adminList
		p6.setAdmin(Arrays.asList("UserA"));
		pdps.add(p0);
		pdps.add(p1);
		pdps.add(p2);
		pdps.add(p3);
		pdps.add(p4);
		pdps.add(p5);
		pdps.add(p6);
		engine.setPDPInterceptors(pdps);
		// Try to get decision
		decision = engine.engineAuthorize(reqAttr, new EntityAttributes(this.resourceOwnerAttrs), null);
		assert (decision != null);
		assert (decision.isDeny());

		// Change UserG to say UserA can access and get a permit
		engine = new PermitOverrideAlg("test chain");
		pdps = new ArrayList<PDPInterceptor>();
		p6.setAccess(Arrays.asList("UserA"));
		pdps.add(p0);
		pdps.add(p1);
		pdps.add(p2);
		pdps.add(p3);
		pdps.add(p4);
		pdps.add(p5);
		pdps.add(p6);
		engine.setPDPInterceptors(pdps);

		// Try to get decision
		decision = engine.engineAuthorize(reqAttr, new EntityAttributes(this.resourceOwnerAttrs), null);
		assertNotNull(decision);
		assertTrue(decision.isPermit());

		engine = new PermitOverrideAlg("test chain");
		pdps = new ArrayList<PDPInterceptor>();
		// scenario 4(c)
		// reset previous permit. should get a deny, already tested
		p6.setAccess(Arrays.asList("FOO"));
		// set contianer to say UserB can adminList, rather than access
		// for permit
		p0.setAdmin(Arrays.asList("UserD", "UserB"));

		pdps.add(p0);
		pdps.add(p1);
		pdps.add(p2);
		pdps.add(p3);
		pdps.add(p4);
		pdps.add(p5);
		pdps.add(p6);
		engine.setPDPInterceptors(pdps);

		// Try to get decision
		decision = engine.engineAuthorize(reqAttr, new EntityAttributes(this.resourceOwnerAttrs),null);
		assert (decision != null);
		assert (decision.isPermit());
	}

	// Test with PIPs establishing different User* are same entities
	// PIP0: token: token1, name=UserD
	// PIP1: token: token2, name=UserC
	// PIP2: token: token1, name=UserB
	// PDP0: container says UserD, UserC can adminList
	// PDP1: UserB says UserA can access
	public void scenario5Test(RequestEntities reqAttr) throws Exception {

		List<PIPInterceptor> pips = new ArrayList<PIPInterceptor>();

		MockPIPImpl i0 = new MockPIPImpl();
		i0.setToken("token3");
		i0.setName("UserD");
		i0.initialize();
		pips.add(i0);

		MockPIPImpl i1 = new MockPIPImpl();
		i1.setToken("Token2");
		i1.setName("UserC");
		i1.initialize();
		pips.add(i1);
		

		MockPIPImpl i2 = new MockPIPImpl();
		i2.setToken("token1");
		i2.setName("UserB");
		i2.initialize();
		pips.add(i2);

		List<PDPInterceptor> pdps = new ArrayList<PDPInterceptor>();

		MockPDPImpl d0 = new MockPDPImpl();
		d0.setIssuer("container");
		d0.setAdmin(Arrays.asList("UserD", "UserC"));
		d0.setOwner(this.resourceOwnerAttrs);
		d0.initialize();
		pdps.add(d0);

		MockPDPImpl d1 = new MockPDPImpl();
		d1.setIssuer("UserB");
		d1.setAccess(Arrays.asList("UserA"));
		d1.setOwner(this.resourceOwnerAttrs);
		d1.initialize();
		pdps.add(d1);

		PermitOverrideAlg engine = new PermitOverrideAlg("test chain");
		engine.setPIPInterceptors(pips);
		engine.setPDPInterceptors(pdps);

		// Try to get decision
		Decision decision = engine.engineAuthorize(reqAttr, new EntityAttributes(this.resourceOwnerAttrs), null);
		assert (decision != null);
		assert (decision.isDeny());

		// setting UserD token to be same as UserB should merge those
		// entries
		i0.setToken("token1");
		engine = new PermitOverrideAlg("test chain");
		engine.setPIPInterceptors(pips);
		engine.setPDPInterceptors(pdps);
		// Try to get decision
		decision = engine.engineAuthorize(reqAttr, new EntityAttributes(this.resourceOwnerAttrs), null);
		assert (decision != null);
		assert (decision.isPermit());
	}
}
