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

import org.springframework.beans.factory.FactoryBean;

import java.util.Calendar;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 26, 2010
 * Time: 5:02:50 PM
 * To change this template use File | Settings | File Templates.
 */
public class MockPDPImplFactory implements FactoryBean<MockPDPImpl> {
    private String issuer;
    private List<String> access;
    private List<String> admin;
    private List<String> denied;
    private IdentityAttributeCollection owner;


    public MockPDPImpl getObject() throws Exception {
        EntityAttributes reqAttrIssuer = init();
        MockPDPImpl p1 = new MockPDPImpl();
        p1.setIssuer(issuer);
        p1.setAdmin(admin);
        p1.setAccess(access);
        p1.setDenied(denied);
        p1.setRequestAttrIssuer(reqAttrIssuer);
        p1.setOwner(owner);
        return p1;
    }

    private EntityAttributes init() throws Exception {
        AttributeIdentifier attrIden = MockPDPImpl.getTestUserAttrIdentifier();
        Attribute resourceOwnerAttr = new Attribute(attrIden, null,
                Calendar.getInstance(), null);
        IdentityAttributeCollection attrCol = new IdentityAttributeCollection();
        attrCol.add(resourceOwnerAttr);

        EntityAttributes resourceOwner = new EntityAttributes(attrCol);

        // request attribute issuer.
        Attribute issuerAttr = new Attribute(attrIden, resourceOwner, Calendar.getInstance(), null);
        attrCol = new IdentityAttributeCollection();
        attrCol.add(issuerAttr);
//        this.reqAttrIssuer = new EntityAttributes(attrCol);
        return new EntityAttributes(attrCol);
    }

    public Class<? extends MockPDPImpl> getObjectType() {
        return MockPDPImpl.class;
    }

    public boolean isSingleton() {
        return true;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setAccess(List<String> access) {
        this.access = access;
    }

    public void setAdmin(List<String> admin) {
        this.admin = admin;
    }

    public void setDenied(List<String> denied) {
        this.denied = denied;
    }

    public void setOwner(IdentityAttributeCollection owner) {
        this.owner = owner;
    }
}
