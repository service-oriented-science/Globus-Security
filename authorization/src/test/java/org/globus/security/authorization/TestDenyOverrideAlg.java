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

import java.util.Calendar;

import org.globus.security.authorization.providers.DenyOverrideAlg;

import org.testng.annotations.Test;

public class TestDenyOverrideAlg {

    EntityAttributes reqAttrIssuer = null;
    EntityAttributes resourceOwner = null;

    @Test
    public void test() throws Exception {

        // resource owner
        AttributeIdentifier attrIden = MockPDPImpl.getTestUserAttrIdentifier();
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


        InterceptorConfig[] pdps = new InterceptorConfig[3];
        pdps[0] = new InterceptorConfig("p1", MockPDPImpl.class.getName());
        pdps[1] = new InterceptorConfig("p2", MockPDPImpl.class.getName());
        pdps[2] = new InterceptorConfig("p3", MockPDPImpl.class.getName());
        AuthorizationConfig authzConfig = new AuthorizationConfig(null, null,
                pdps);

        // Permit
        ChainConfig chainConfig = new MockChainConfig();
        chainConfig.setProperty("p1", "issuer", "Issuer1");
        chainConfig.setProperty("p1", "access", "UserA");
        chainConfig.setProperty("p1", "denied", "UserD");
        chainConfig.setProperty("p1", "reqIssuer", this.reqAttrIssuer);
        chainConfig.setProperty("p2", "issuer", "Issuer2");
        chainConfig.setProperty("p2", "access", "UserA");
        chainConfig.setProperty("p2", "reqIssuer", this.reqAttrIssuer);
        chainConfig.setProperty("p3", "issuer", "Issuer3");
        chainConfig.setProperty("p3", "access", "UserA");
        chainConfig.setProperty("p3", "reqIssuer", this.reqAttrIssuer);

        // Requestor userA
        Attribute attr = new Attribute(attrIden, this.reqAttrIssuer,
                Calendar.getInstance(), null);
        attr.addAttributeValue("UserA");
        IdentityAttributeCollection coll = new IdentityAttributeCollection();
        coll.add(attr);
        EntityAttributes requestor = new EntityAttributes(coll);
        RequestEntities reqAttr =
                new RequestEntities(requestor, null, null, null);

        DenyOverrideAlg engine = new DenyOverrideAlg();
        engine.engineInitialize("chain name", authzConfig, chainConfig);

        // Try to get decision.
        Decision decision = engine.engineAuthorize(reqAttr, this.resourceOwner);
        assert (decision != null);
        assert (decision.isPermit());

        // Deny
        chainConfig = new MockChainConfig();
        chainConfig.setProperty("p1", "issuer", "Issuer1");
        chainConfig.setProperty("p1", "access", "UserA");
        chainConfig.setProperty("p1", "denied", "UserD");
        chainConfig.setProperty("p1", "reqIssuer", this.reqAttrIssuer);
        chainConfig.setProperty("p2", "issuer", "Issuer2");
        chainConfig.setProperty("p2", "access", "UserA");
        chainConfig.setProperty("p2", "reqIssuer", this.reqAttrIssuer);
        chainConfig.setProperty("p3", "issuer", "Issuer3");
        chainConfig.setProperty("p3", "denied", "UserA");
        chainConfig.setProperty("p3", "reqIssuer", this.reqAttrIssuer);

        // Try to get decision
        DenyOverrideAlg engine1 = new DenyOverrideAlg();
        engine1.engineInitialize("chain name", authzConfig, chainConfig);

        Decision decision1 = engine1.engineAuthorize(reqAttr,
                this.resourceOwner);
        assert (decision1 != null);
        assert (decision1.isDeny());

        // indeterminate
        chainConfig = new MockChainConfig();
        chainConfig.setProperty("p1", "issuer", "Issuer1");
        chainConfig.setProperty("p1", "access", "UserC");
        chainConfig.setProperty("p1", "denied", "UserD");
        chainConfig.setProperty("p1", "reqIssuer", this.reqAttrIssuer);
        chainConfig.setProperty("p2", "issuer", "Issuer2");
        chainConfig.setProperty("p2", "access", "UserC");
        chainConfig.setProperty("p2", "reqIssuer", this.reqAttrIssuer);
        chainConfig.setProperty("p3", "issuer", "Issuer3");
        chainConfig.setProperty("p3", "admin", "UserA");
        chainConfig.setProperty("p3", "reqIssuer", this.reqAttrIssuer);

        // Try to get decision
        DenyOverrideAlg engine2 = new DenyOverrideAlg();
        engine2.engineInitialize("chain name", authzConfig, chainConfig);

        Decision decision2 = engine2.engineAuthorize(reqAttr,
                this.resourceOwner);
        assert (decision2 != null);
        assert (decision2.getDecision() == Decision.INDETERMINATE);
    }
}