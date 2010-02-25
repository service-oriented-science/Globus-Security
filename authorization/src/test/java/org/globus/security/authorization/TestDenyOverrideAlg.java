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

import org.globus.security.authorization.providers.DenyOverrideAlg;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

import static org.testng.Assert.*;

public class TestDenyOverrideAlg {

    AttributeIdentifier attrIden;
    EntityAttributes reqAttrIssuer = null;
    EntityAttributes resourceOwner = null;
    RequestEntities reqAttr = null;

    @BeforeClass
    public void setup() throws Exception {
        // resource owner
        attrIden = MockPDPImpl.getTestUserAttrIdentifier();
        Attribute resourceOwnerAttr = new Attribute(attrIden, null,
                Calendar.getInstance(), null);
        IdentityAttributeCollection attrCol = new IdentityAttributeCollection();
        attrCol.add(resourceOwnerAttr);

        this.resourceOwner = new EntityAttributes(attrCol);

        // request attribute issuer.
        Attribute issuerAttr = new Attribute(attrIden, this.resourceOwner,
                Calendar.getInstance(), null);
        attrCol = new IdentityAttributeCollection();
        attrCol.add(issuerAttr);
        this.reqAttrIssuer = new EntityAttributes(attrCol);

// Requestor userA
        Attribute attr = new Attribute(attrIden, this.reqAttrIssuer, Calendar.getInstance(), null);
        attr.addAttributeValue("UserA");
        IdentityAttributeCollection coll = new IdentityAttributeCollection();
        coll.add(attr);
        EntityAttributes requestor = new EntityAttributes(coll);
        reqAttr = new RequestEntities(requestor, null, null, null);

    }

    @Test
    public void test1() throws Exception {

        List<MockPDPImpl> pdps = new ArrayList<MockPDPImpl>();
        MockPDPImpl p1 = new MockPDPImpl();
        p1.setIssuer("Issuer1");
        p1.setAccess(Arrays.asList("UserA"));
        p1.setDenied(Arrays.asList("UserD"));
        p1.setRequestAttrIssuer(this.reqAttrIssuer);
        pdps.add(p1);

        MockPDPImpl p2 = new MockPDPImpl();
        p2.setIssuer("Issuer2");
        p2.setAccess(Arrays.asList("UserA"));
        p2.setRequestAttrIssuer(this.reqAttrIssuer);
        pdps.add(p2);

        MockPDPImpl p3 = new MockPDPImpl();
        p3.setIssuer("Issuer3");
        p3.setAccess(Arrays.asList("UserA"));
        p3.setRequestAttrIssuer(this.reqAttrIssuer);
        pdps.add(p3);

        // Permit
        DenyOverrideAlg engine = new DenyOverrideAlg("chain name");

        engine.setPDPInterceptors(pdps);
                
        // Try to get decision.
        Decision decision = engine.engineAuthorize(reqAttr, this.resourceOwner);
        assertNotNull(decision);
        assertTrue(decision.isPermit());
    }

    @Test
    public void test2() throws Exception {
        List<MockPDPImpl> pdps = new ArrayList<MockPDPImpl>();


        MockPDPImpl p1 = new MockPDPImpl();
        p1.setIssuer("Issuer1");
        p1.setAccess(Arrays.asList("UserA"));
        p1.setDenied(Arrays.asList("UserD"));
        p1.setRequestAttrIssuer(this.reqAttrIssuer);
        pdps.add(p1);

        MockPDPImpl p2 = new MockPDPImpl();
        p2.setIssuer("Issuer2");
        p2.setAccess(Arrays.asList("UserA"));
        p2.setRequestAttrIssuer(this.reqAttrIssuer);
        pdps.add(p2);

        MockPDPImpl p3 = new MockPDPImpl();
        p3.setIssuer("Issuer3");
        p3.setDenied(Arrays.asList("UserA"));
        p3.setRequestAttrIssuer(this.reqAttrIssuer);
        pdps.add(p3);

        DenyOverrideAlg engine1 = new DenyOverrideAlg("chain name");

        engine1.setPDPInterceptors(pdps);
        // Try to get decision

        Decision decision1 = engine1.engineAuthorize(reqAttr, this.resourceOwner);
        assertNotNull(decision1);
        assertTrue(decision1.isDeny());
    }

    @Test
    public void test3() throws Exception {
        List<MockPDPImpl> pdps = new ArrayList<MockPDPImpl>();

        MockPDPImpl p1 = new MockPDPImpl();
        p1.setIssuer("Issuer1");
        p1.setAccess(Arrays.asList("UserC"));
        p1.setDenied(Arrays.asList("UserD"));
        p1.setRequestAttrIssuer(this.reqAttrIssuer);
        pdps.add(p1);

        MockPDPImpl p2 = new MockPDPImpl();
        p2.setIssuer("Issuer2");
        p2.setAccess(Arrays.asList("UserC"));
        p2.setRequestAttrIssuer(this.reqAttrIssuer);
        pdps.add(p2);

        MockPDPImpl p3 = new MockPDPImpl();
        p3.setIssuer("Issuer3");
        p3.setAdmin(Arrays.asList("UserA"));
        p3.setRequestAttrIssuer(this.reqAttrIssuer);
        pdps.add(p3);


        // indeterminate

        // Try to get decision
        DenyOverrideAlg engine2 = new DenyOverrideAlg("chain name");
        engine2.setPDPInterceptors(pdps);

        Decision decision2 = engine2.engineAuthorize(reqAttr, this.resourceOwner);
        assertNotNull(decision2);
        assertEquals(decision2.getDecision(), Decision.INDETERMINATE);
    }
}
