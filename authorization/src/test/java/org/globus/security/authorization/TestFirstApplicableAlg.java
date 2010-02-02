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

import org.globus.security.authorization.providers.FirstApplicableAlg;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Iterator;

public class TestFirstApplicableAlg {

    EntityAttributes reqAttrIssuer = null;
    EntityAttributes resourceOwner = null;

    @Test
    public void testFirstApplicable() throws Exception {
        FirstApplicableAlg engine = new FirstApplicableAlg("chain name");

        // resource owner
        AttributeIdentifier attrIden = MockPDPImpl.getTestUserAttrIdentifier();
        Attribute resourceOwnerAttr = new Attribute(attrIden, null, Calendar.getInstance(), null);
        IdentityAttributeCollection attrCol = new IdentityAttributeCollection();
        attrCol.add(resourceOwnerAttr);

        this.resourceOwner = new EntityAttributes(attrCol);

        // request attribute issuer.
        Attribute issuerAttr = new Attribute(attrIden, this.resourceOwner,
                Calendar.getInstance(), null);
        attrCol = new IdentityAttributeCollection();
        attrCol.add(issuerAttr);
        this.reqAttrIssuer = new EntityAttributes(attrCol);


        MockPDPImpl p1 = new MockPDPImpl();
        p1.setIssuer("Issuer1");
        p1.setAccess(Arrays.asList("UserC"));
        p1.setDenied(Arrays.asList("UserD"));
        p1.setRequestAttrIssuer(this.reqAttrIssuer);
        engine.addPDP(new InterceptorConfig<MockPDPImpl>("p1", p1));

        MockPDPImpl p2 = new MockPDPImpl();
        p2.setIssuer("Issuer2");
        p2.setAccess(Arrays.asList("UserA"));
        p2.setRequestAttrIssuer(this.reqAttrIssuer);
        engine.addPDP(new InterceptorConfig<MockPDPImpl>("p2", p2));

        MockPDPImpl p3 = new MockPDPImpl();
        p3.setIssuer("Issuer3");
        p3.setDenied(Arrays.asList("Issuer3"));
        p3.setRequestAttrIssuer(this.reqAttrIssuer);
        engine.addPDP(new InterceptorConfig<MockPDPImpl>("p3", p3));

        // Requestor userA
        Attribute attr = new Attribute(attrIden, this.reqAttrIssuer,
                Calendar.getInstance(), null);
        attr.addAttributeValue("UserA");
        IdentityAttributeCollection coll = new IdentityAttributeCollection();
        coll.add(attr);
        EntityAttributes requestor = new EntityAttributes(coll);
        RequestEntities reqAttr =
                new RequestEntities(requestor, null, null, null);


        // Try to get decision.
        Decision decision = engine.engineAuthorize(reqAttr, this.resourceOwner);
        assert (decision != null);
        assert (decision.isPermit());
        EntityAttributes retEntity = decision.getIssuer();
        assert (retEntity != null);
        assert (retEntity.getIdentityAttributes() != null);
        Iterator iterator = retEntity.getIdentityAttributes().
                getAttributes(attrIden).iterator();
        Attribute retIssuer = null;
        // Not dealing with multiple issuers of same attribute in this test case
        if (iterator.hasNext()) {
            retIssuer = (Attribute) iterator.next();
        }
        assert (retIssuer != null);
        String retIssuerVal = (String) (retIssuer.getAttributeValueSet()
                .iterator().next());
        assert ("Issuer2".equals(retIssuerVal));


        FirstApplicableAlg engine1 = new FirstApplicableAlg("chain name");

        p1 = new MockPDPImpl();
        p1.setIssuer("Issuer1");
        p1.setAccess(Arrays.asList("UserC"));
        p1.setDenied(Arrays.asList("UserD"));
        p1.setRequestAttrIssuer(this.reqAttrIssuer);
        engine1.addPDP(new InterceptorConfig<MockPDPImpl>("p1", p1));

        p2 = new MockPDPImpl();
        p2.setIssuer("Issuer2");
        p2.setAccess(Arrays.asList("UserC"));
        p2.setRequestAttrIssuer(this.reqAttrIssuer);
        engine1.addPDP(new InterceptorConfig<MockPDPImpl>("p2", p2));

        p3 = new MockPDPImpl();
        p3.setIssuer("Issuer3");
        p3.setDenied(Arrays.asList("UserA"));
        p3.setRequestAttrIssuer(this.reqAttrIssuer);
        engine1.addPDP(new InterceptorConfig<MockPDPImpl>("p3", p3));

        // Try to get decision
        engine1.engineInitialize("chain name");

        Decision decision1 = engine1.engineAuthorize(reqAttr,
                this.resourceOwner);
        assert (decision1 != null);
        assert (decision1.isDeny());
        EntityAttributes retEntity1 = decision1.getIssuer();
        assert (retEntity1 != null);
        assert (retEntity1.getIdentityAttributes() != null);
        iterator = retEntity1.getIdentityAttributes().
                getAttributes(attrIden).iterator();
        Attribute retIssuer1 = null;
        // Not dealing with multiple issuers of same attribute in this test case
        if (iterator.hasNext()) {
            retIssuer1 = (Attribute) iterator.next();
        }
        assert (retIssuer1 != null);
        String retIssuerVal1 = (String) (retIssuer1.getAttributeValueSet()
                .iterator().next());
        assert ("Issuer3".equals(retIssuerVal1));

        FirstApplicableAlg engine2 = new FirstApplicableAlg("chain name");


        // indeterminate
        p1 = new MockPDPImpl();
        p1.setIssuer("Issuer1");
        p1.setAccess(Arrays.asList("UserC"));
        p1.setDenied(Arrays.asList("UserD"));
        p1.setRequestAttrIssuer(this.reqAttrIssuer);
        engine2.addPDP(new InterceptorConfig<MockPDPImpl>("p1", p1));

        p2 = new MockPDPImpl();
        p2.setIssuer("Issuer2");
        p2.setAccess(Arrays.asList("UserC"));
        p2.setRequestAttrIssuer(this.reqAttrIssuer);
        engine2.addPDP(new InterceptorConfig<MockPDPImpl>("p2", p2));

        p3 = new MockPDPImpl();
        p3.setIssuer("Issuer3");
        p3.setAdmin(Arrays.asList("UserA"));
        p3.setRequestAttrIssuer(this.reqAttrIssuer);
        engine2.addPDP(new InterceptorConfig<MockPDPImpl>("p3", p3));

        // Try to get decision
        engine2.engineInitialize("chain name");

        Decision decision2 = engine2.engineAuthorize(reqAttr,
                this.resourceOwner);
        assert (decision2 != null);
        assert (decision2.getDecision() == Decision.INDETERMINATE);

    }
}
