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

import org.globus.security.authorization.providers.PermitOverrideAlg;

import org.testng.annotations.Test;

public class TestPermitOverrideAlg {

    AttributeIdentifier attrIden = null;
    IdentityAttributeCollection resourceOwnerAttrs = null;

    @Test
    public void test() throws Exception {

        this.attrIden = MockPDPImpl.getTestUserAttrIdentifier();

        // Requestor userA
        Attribute attr = new Attribute(this.attrIden, null,
                Calendar.getInstance(), null);
        attr.addAttributeValue("UserA");
        IdentityAttributeCollection coll = new IdentityAttributeCollection();
        coll.add(attr);
        EntityAttributes requestor = new EntityAttributes(coll);
        RequestEntities reqAttr =
                new RequestEntities(requestor, null, null, null);

        // resource owner

        AttributeIdentifier attrIden = MockPDPImpl.getTestUserAttrIdentifier();
        Attribute ownerAttr = new Attribute(attrIden, null,
                Calendar.getInstance(), null);
        IdentityAttributeCollection attrCol = new IdentityAttributeCollection();
        attrCol.add(ownerAttr);
        EntityAttributes owner = new EntityAttributes(attrCol);

        Attribute resourceOwnerAttr =
                new Attribute(attrIden, owner, Calendar.getInstance(), null);

        this.resourceOwnerAttrs = new IdentityAttributeCollection();
        this.resourceOwnerAttrs.add(resourceOwnerAttr);

        scenario1Test(reqAttr);
        scenario2Test(reqAttr);
        scenario3Test(reqAttr);
        scenario4Test(reqAttr);
        scenario5Test(reqAttr);
    }

    // PDP0: resourceOwner says UserB can admin
    // PDP1: UserB says UserA can access
    public void scenario1Test(RequestEntities reqAttr) throws Exception {

        InterceptorConfig[] pdps = new InterceptorConfig[2];
        pdps[0] = new InterceptorConfig("p0", MockPDPImpl.class.getName());
        pdps[1] = new InterceptorConfig("p1", MockPDPImpl.class.getName());
        AuthorizationConfig authzConfig = new AuthorizationConfig(null, null,
                pdps);

        ChainConfig chainConfig = new MockChainConfig();
        chainConfig.setProperty("p0", "issuer", "container");
        chainConfig.setProperty("p0", "admin", "UserB");
        chainConfig.setProperty("p0", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p1", "issuer", "UserB");
        chainConfig.setProperty("p1", "access", "UserA");
        chainConfig.setProperty("p1", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);


        PermitOverrideAlg engine = new PermitOverrideAlg();
        engine.engineInitialize("test chain", authzConfig, chainConfig);

        // Try to get decision
        Decision decision = engine.
                engineAuthorize(reqAttr,
                        new EntityAttributes(this.resourceOwnerAttrs));
        assert (decision != null);
        assert (decision.isPermit());
        EntityAttributes retEntity = decision.getIssuer();
        assert (retEntity != null);
        assert (retEntity.getIdentityAttributes() != null);
        IdentityAttributeCollection idenCol =
                retEntity.getIdentityAttributes();
        assert (idenCol != null);
        assert (idenCol.isSameEntity(this.resourceOwnerAttrs));
    }

    // Use of denied list
    // PDP0: container says UserB can admin
    // PDP1: UserB says UserD can admin
    // PDP2: USerC says UserE can admin
    // PDP3: UserE says UserA can access
    // PDP4: USerF says UserA can access
    // PDP5: UserD says UserF can admin
    public void scenario2Test(RequestEntities reqAttr) throws Exception {

        InterceptorConfig[] pdps = new InterceptorConfig[6];
        pdps[0] = new InterceptorConfig("p0", MockPDPImpl.class.getName());
        pdps[1] = new InterceptorConfig("p1", MockPDPImpl.class.getName());
        pdps[2] = new InterceptorConfig("p2", MockPDPImpl.class.getName());
        pdps[3] = new InterceptorConfig("p3", MockPDPImpl.class.getName());
        pdps[4] = new InterceptorConfig("p4", MockPDPImpl.class.getName());
        pdps[5] = new InterceptorConfig("p5", MockPDPImpl.class.getName());
        AuthorizationConfig authzConfig = new AuthorizationConfig(null, null,
                pdps);

        ChainConfig chainConfig = new MockChainConfig();
        chainConfig.setProperty("p0", "issuer", MockPDPImpl.OWNER);
        chainConfig.setProperty("p0", "admin", "UserB");
        chainConfig.setProperty("p0", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p1", "issuer", "UserB");
        chainConfig.setProperty("p1", "admin", "UserD");
        chainConfig.setProperty("p1", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p2", "issuer", "UserC");
        chainConfig.setProperty("p2", "admin", "UserE");
        chainConfig.setProperty("p2", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p3", "issuer", "UserE");
        chainConfig.setProperty("p3", "access", "UserA");
        chainConfig.setProperty("p3", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p4", "issuer", "UserF");
        chainConfig.setProperty("p4", "access", "UserA");
        chainConfig.setProperty("p4", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p5", "issuer", "UserD");
        chainConfig.setProperty("p5", "admin", "UserF");
        chainConfig.setProperty("p5", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);

        PermitOverrideAlg engine = new PermitOverrideAlg();
        engine.engineInitialize("test chain", authzConfig, chainConfig);

        // Try to get decision
        Decision decision = engine.
                engineAuthorize(reqAttr,
                        new EntityAttributes(this.resourceOwnerAttrs));
        assert (decision != null);
        assert (decision.isPermit());
        EntityAttributes retEntity = decision.getIssuer();
        assert (retEntity != null);
        assert (retEntity.getIdentityAttributes() != null);
        IdentityAttributeCollection idenCol =
                retEntity.getIdentityAttributes();
        assert (idenCol != null);
        assert (idenCol.isSameEntity(this.resourceOwnerAttrs));

        // deny if UserD does not grant rights on UserF
        chainConfig.setProperty("p5", "admin", "UserG");
        engine = new PermitOverrideAlg();
        engine.engineInitialize("test chain", authzConfig, chainConfig);
        decision = engine.
                engineAuthorize(reqAttr,
                        new EntityAttributes(this.resourceOwnerAttrs));
        assert (decision != null);
        assert (decision.isDeny());

    }

    // (Scenario 3) Resource owner in middle of chain (and denied list used)
    // PDP0: container says UserB can acess
    // PDP1: UserC says UserE can admin
    // PDP2: UserE says UserA can access
    // PDP3: container says UserD can admin
    // PDP4: USerF says UserA can access
    // PDP5: UserD says UserF can admin (take this off to see no chain
    // and deny)
    public void scenario3Test(RequestEntities reqAttr) throws Exception {

        InterceptorConfig[] pdps = new InterceptorConfig[6];
        pdps[0] = new InterceptorConfig("p0", MockPDPImpl.class.getName());
        pdps[1] = new InterceptorConfig("p1", MockPDPImpl.class.getName());
        pdps[2] = new InterceptorConfig("p2", MockPDPImpl.class.getName());
        pdps[3] = new InterceptorConfig("p3", MockPDPImpl.class.getName());
        pdps[4] = new InterceptorConfig("p4", MockPDPImpl.class.getName());
        pdps[5] = new InterceptorConfig("p5", MockPDPImpl.class.getName());
        AuthorizationConfig authzConfig = new AuthorizationConfig(null, null,
                pdps);

        ChainConfig chainConfig = new MockChainConfig();
        chainConfig.setProperty("p0", "issuer", "container");
        chainConfig.setProperty("p0", "access", "UserB");
        chainConfig.setProperty("p0", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p1", "issuer", "UserC");
        chainConfig.setProperty("p1", "admin", "UserE");
        chainConfig.setProperty("p1", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p2", "issuer", "UserE");
        chainConfig.setProperty("p2", "access", "UserA");
        chainConfig.setProperty("p2", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p3", "issuer", "container");
        chainConfig.setProperty("p3", "admin", "UserD");
        chainConfig.setProperty("p3", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p4", "issuer", "UserF");
        chainConfig.setProperty("p4", "access", "UserA");
        chainConfig.setProperty("p4", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p5", "issuer", "UserD");
        chainConfig.setProperty("p5", "admin", "UserF");
        chainConfig.setProperty("p6", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);

        PermitOverrideAlg engine = new PermitOverrideAlg();
        engine.engineInitialize("test chain", authzConfig, chainConfig);

        // Try to get decision
        Decision decision = engine.
                engineAuthorize(reqAttr,
                        new EntityAttributes(this.resourceOwnerAttrs));
        assert (decision != null);
        assert (decision.isPermit());
        EntityAttributes retEntity = decision.getIssuer();
        assert (retEntity != null);
        assert (retEntity.getIdentityAttributes() != null);
        IdentityAttributeCollection idenCol =
                retEntity.getIdentityAttributes();
        assert (idenCol != null);
        assert (idenCol.isSameEntity(this.resourceOwnerAttrs));
    }

    // (Scenario 4) Ensure right question (admin or access) is asked
    // at correct points
    // PDP0: container  says UserD can admin
    //                  says UserB can access
    // PDP1: UserF says UserA can access
    // PDP2: UserB says UserE can admin
    // PDP3: UserC says UserG can admin
    // PDP4: UserD says UserC can admin
    //             says UserF can access
    // PDP5: UserE says UserF can admin
    // PDP6: UserG says UserF, UserA can admin
    // a) container->UserD->UserC->UserG->UserF->UserA
    // b) container->UserD->UserC->UserG-> but UserG says UserA can admin
    // not access
    // c) UserB->UserE->UserF->UserA, but container says UserB can
    // access, not admin
    public void scenario4Test(RequestEntities reqAttr) throws Exception {

        InterceptorConfig[] pdps = new InterceptorConfig[7];
        pdps[0] = new InterceptorConfig("p0", MockPDPImpl.class.getName());
        pdps[1] = new InterceptorConfig("p1", MockPDPImpl.class.getName());
        pdps[2] = new InterceptorConfig("p2", MockPDPImpl.class.getName());
        pdps[3] = new InterceptorConfig("p3", MockPDPImpl.class.getName());
        pdps[4] = new InterceptorConfig("p4", MockPDPImpl.class.getName());
        pdps[5] = new InterceptorConfig("p5", MockPDPImpl.class.getName());
        pdps[6] = new InterceptorConfig("p6", MockPDPImpl.class.getName());
        AuthorizationConfig authzConfig = new AuthorizationConfig(null, null,
                pdps);

        ChainConfig chainConfig = new MockChainConfig();

        chainConfig.setProperty("p0", "issuer", "container");
        chainConfig.setProperty("p0", "admin", "UserD");
        chainConfig.setProperty("p0", "access", "UserB");
        chainConfig.setProperty("p0", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p1", "issuer", "UserF");
        chainConfig.setProperty("p1", "access", "UserA");
        chainConfig.setProperty("p1", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p2", "issuer", "UserB");
        chainConfig.setProperty("p2", "admin", "UserE");
        chainConfig.setProperty("p2", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p3", "issuer", "UserC");
        chainConfig.setProperty("p3", "admin", "UserG");
        chainConfig.setProperty("p3", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p4", "issuer", "UserD");
        chainConfig.setProperty("p4", "access", "UserF");
        chainConfig.setProperty("p4", "admin", "UserC");
        chainConfig.setProperty("p4", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p5", "issuer", "UserE");
        chainConfig.setProperty("p5", "admin", "UserF");
        chainConfig.setProperty("p5", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        chainConfig.setProperty("p6", "issuer", "UserG");
        chainConfig.setProperty("p6", "admin", "UserF UserA");
        chainConfig.setProperty("p6", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);
        PermitOverrideAlg engine = new PermitOverrideAlg();
        engine.engineInitialize("test chain", authzConfig, chainConfig);

        // Try to get decision
        Decision decision = engine.
                engineAuthorize(reqAttr,
                        new EntityAttributes(this.resourceOwnerAttrs));
        assert (decision != null);
        assert (decision.isPermit());

        // scenario 4(b)
        // Disable current premit chain: PDP6: UserG says UserA can admin
        chainConfig.setProperty("p6", "admin", "UserA");
        engine = new PermitOverrideAlg();
        engine.engineInitialize("test chain", authzConfig, chainConfig);

        // Try to get decision
        decision = engine.
                engineAuthorize(reqAttr,
                        new EntityAttributes(this.resourceOwnerAttrs));
        assert (decision != null);
        assert (decision.isDeny());

        // Change UserG to say UserA can access and get a permit
        chainConfig.setProperty("p6", "access", "UserA");
        engine = new PermitOverrideAlg();
        engine.engineInitialize("test chain", authzConfig, chainConfig);

        // Try to get decision
        decision = engine.
                engineAuthorize(reqAttr,
                        new EntityAttributes(this.resourceOwnerAttrs));
        assert (decision != null);
        assert (decision.isPermit());

        // scenario 4(c)
        // reset previous permit. should get a deny, already tested
        chainConfig.setProperty("p6", "access", "FOO");
        // set contianer to say UserB can admin, rather than access
        // for permit
        chainConfig.setProperty("p0", "admin", "UserD UserB");

        engine = new PermitOverrideAlg();
        engine.engineInitialize("test chain", authzConfig, chainConfig);

        // Try to get decision
        decision = engine.
                engineAuthorize(reqAttr,
                        new EntityAttributes(this.resourceOwnerAttrs));
        assert (decision != null);
        assert (decision.isPermit());
    }

    // Test with PIPs establishing different User* are same entities
    // PIP0: token: token1, name=UserD
    // PIP1: token: token2, name=UserC
    // PIP2: token: token1, name=UserB
    // PDP0: container says UserD, UserC can admin
    // PDP1: UserB says UserA can access
    public void scenario5Test(RequestEntities reqAttr) throws Exception {

        InterceptorConfig[] pips = new InterceptorConfig[3];
        pips[0] = new InterceptorConfig("i0", MockPIPImpl.class.getName());
        pips[1] = new InterceptorConfig("i1", MockPIPImpl.class.getName());
        pips[2] = new InterceptorConfig("i2", MockPIPImpl.class.getName());

        InterceptorConfig[] pdps = new InterceptorConfig[2];
        pdps[0] = new InterceptorConfig("d0", MockPDPImpl.class.getName());
        pdps[1] = new InterceptorConfig("d1", MockPDPImpl.class.getName());

        AuthorizationConfig authzConfig = new AuthorizationConfig(null, pips,
                pdps);

        ChainConfig chainConfig = new MockChainConfig();
        chainConfig.setProperty("d0", "issuer", "container");
        chainConfig.setProperty("d0", "admin", "UserD UserC");
        chainConfig.setProperty("d0", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);

        chainConfig.setProperty("d1", "issuer", "UserB");
        chainConfig.setProperty("d1", "access", "UserA");
        chainConfig.setProperty("d1", MockPDPImpl.OWNER,
                this.resourceOwnerAttrs);

        chainConfig.setProperty("i0", "token", "token3");
        chainConfig.setProperty("i0", "name", "UserD");

        chainConfig.setProperty("i1", "token", "token2");
        chainConfig.setProperty("i1", "name", "UserC");

        chainConfig.setProperty("i2", "token", "token1");
        chainConfig.setProperty("i2", "name", "UserB");

        PermitOverrideAlg engine = new PermitOverrideAlg();
        engine.engineInitialize("test chain", authzConfig, chainConfig);


        // Try to get decision
        Decision decision = engine.
                engineAuthorize(reqAttr,
                        new EntityAttributes(this.resourceOwnerAttrs));
        assert (decision != null);
        assert (decision.isDeny());

        // setting UserD token to be same as UserB should merge those
        // entries
        chainConfig.setProperty("i0", "token", "token1");
        engine = new PermitOverrideAlg();
        engine.engineInitialize("test chain", authzConfig, chainConfig);

        // Try to get decision
        decision = engine.
                engineAuthorize(reqAttr,
                        new EntityAttributes(this.resourceOwnerAttrs));
        assert (decision != null);
        assert (decision.isPermit());
    }
}
