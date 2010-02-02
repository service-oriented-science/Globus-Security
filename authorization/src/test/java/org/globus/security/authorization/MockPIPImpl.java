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

import java.net.URI;
import java.util.Calendar;
import java.util.List;
import java.util.StringTokenizer;
import java.util.Vector;

public class MockPIPImpl implements PIPInterceptor {

    private int initCount = 0;

    private String token;
    private String name;
    private String resource;
    private String resGroup;
    private String action;
    private String actionGp;
    private AttributeIdentifier tokenIden;
    private AttributeIdentifier userIden;
    private AttributeIdentifier resourceIden;
    private AttributeIdentifier resGroupIden;
    private AttributeIdentifier actionIden;
    private AttributeIdentifier actionGroupIden;
    private Calendar now;
    private EntityAttributes issuer;

    // This method sets up URIs to use in attribute identifiers and an issuer
    // entity. For every instance of MockPIPImpl the generated objects will be
    // equal.
    public void setupURI() throws InitializeException {

        URI DUMMY_ATTRIBUTE_URI;
        URI TOKEN_ATTRIBUTE_URI;
        URI RES_ATTRIBUTE_URI;
        URI RES_GP_ATTRIBUTE_URI;
        URI ACTION_ATTRIBUTE_URI;
        URI ACTION_GP_ATTRIBUTE_URI;

        try {
            DUMMY_ATTRIBUTE_URI = new URI("urn:globus:4.0:test:user");
            TOKEN_ATTRIBUTE_URI = new URI("urn:globus:4.0:test:token");
            RES_ATTRIBUTE_URI = new URI("urn:globus:4.0:test:resource");
            RES_GP_ATTRIBUTE_URI = new URI("urn:globus:4.0:test:resGp");
            ACTION_ATTRIBUTE_URI = new URI("urn:globus:4.0:test:action");
            ACTION_GP_ATTRIBUTE_URI = new URI("urn:globus:4.0:test:actionGp");

            AttributeIdentifier attrIdentifier =
                    new AttributeIdentifier(TestConstants.ISSUER_ID,
                            TestConstants.STRING_DATATYPE_URI,
                            true);
            Attribute attribute = new Attribute(attrIdentifier, null,
                    Calendar.getInstance(), null);
            IdentityAttributeCollection identityAttributes =
                    new IdentityAttributeCollection();
            identityAttributes.add(attribute);
            this.issuer = new EntityAttributes(identityAttributes, null);
        } catch (Exception exp) {
            throw new InitializeException("bad URI", exp);
        }

        tokenIden = new AttributeIdentifier(TOKEN_ATTRIBUTE_URI,
                TestConstants.STRING_DATATYPE_URI,
                true);
        userIden = new AttributeIdentifier(DUMMY_ATTRIBUTE_URI,
                TestConstants.STRING_DATATYPE_URI,
                true);

        resourceIden =
                new AttributeIdentifier(RES_ATTRIBUTE_URI,
                        TestConstants.STRING_DATATYPE_URI,
                        true);
        resGroupIden =
                new AttributeIdentifier(RES_GP_ATTRIBUTE_URI,
                        TestConstants.STRING_DATATYPE_URI,
                        true);

        actionIden = new AttributeIdentifier(ACTION_ATTRIBUTE_URI,
                TestConstants.STRING_DATATYPE_URI,
                true);
        actionGroupIden =
                new AttributeIdentifier(ACTION_GP_ATTRIBUTE_URI,
                        TestConstants.STRING_DATATYPE_URI,
                        true);

    }

    public void initialize(String chainName, String prefix_) throws InitializeException {

        initCount++;


        setupURI();

        now = Calendar.getInstance();

//        String prefix = prefix_;
    }

    public NonRequestEntities collectAttributes(RequestEntities requestAttr)
            throws AttributeException {

        IdentityAttributeCollection subCol = new IdentityAttributeCollection();
        List<EntityAttributes> subjectColl = new Vector<EntityAttributes>();
        // add attribute for token
        if (this.token != null) {
            Attribute tokenAttr = new Attribute(this.tokenIden, this.issuer, now, null);
            StringTokenizer tok = new StringTokenizer(this.token);
            while (tok.hasMoreTokens()) {
                tokenAttr.addAttributeValue(tok.nextToken());
            }
            subCol.add(tokenAttr);
        }
        // add attribute for name
        if (this.name != null) {
            Attribute attr = new Attribute(this.userIden, this.issuer, now,
                    null);
            StringTokenizer tok = new StringTokenizer(this.name);
            while (tok.hasMoreTokens()) {
                attr.addAttributeValue(tok.nextToken());
            }
            subCol.add(attr);
        }

        subjectColl.add(new EntityAttributes(subCol));

        IdentityAttributeCollection resCol = new IdentityAttributeCollection();
        List<EntityAttributes> resCol1 = new Vector<EntityAttributes>();
        if (this.resource != null) {
            Attribute attr = new Attribute(this.resourceIden, this.issuer, now, null);
            StringTokenizer tok = new StringTokenizer(this.resource);
            while (tok.hasMoreTokens()) {
                attr.addAttributeValue(tok.nextToken());
            }
            resCol.add(attr);
        }
        if (this.resGroup != null) {
            Attribute attr = new Attribute(this.resGroupIden, this.issuer, now,
                    null);
            StringTokenizer tok = new StringTokenizer(this.resGroup);
            while (tok.hasMoreTokens()) {
                attr.addAttributeValue(tok.nextToken());
            }
            resCol.add(attr);
        }
        if (resCol.size() > 0) {
            resCol1.add(new EntityAttributes(resCol));
        }

        IdentityAttributeCollection actionCol = new IdentityAttributeCollection();

        List<EntityAttributes> actionCol1 = new Vector<EntityAttributes>();
        if (this.action != null) {
            Attribute attr = new Attribute(this.actionIden, this.issuer, now, null);
            StringTokenizer tok = new StringTokenizer(this.action);
            while (tok.hasMoreTokens()) {
                attr.addAttributeValue(tok.nextToken());
            }
            actionCol.add(attr);
        }
        if (this.actionGp != null) {
            Attribute attr = new Attribute(this.actionGroupIden, this.issuer, now, null);
            StringTokenizer tok = new StringTokenizer(this.actionGp);
            while (tok.hasMoreTokens()) {
                attr.addAttributeValue(tok.nextToken());
            }
            actionCol.add(attr);
        }
        if (actionCol.size() > 0) {
            actionCol1.add(new EntityAttributes(actionCol));
        }

        return new NonRequestEntities(subjectColl, actionCol1, resCol1);
    }

    public void close() {
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public void setResGroup(String resGroup) {
        this.resGroup = resGroup;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public void setActionGp(String actionGp) {
        this.actionGp = actionGp;
    }

    public AttributeIdentifier getTokenIden() {
        return this.tokenIden;
    }

    public AttributeIdentifier getUserIden() {
        return this.userIden;
    }

    public AttributeIdentifier getResourceIden() {
        return this.resourceIden;
    }

    public AttributeIdentifier getResourceGpIden() {
        return this.resGroupIden;
    }

    public AttributeIdentifier getActionIden() {
        return this.actionIden;
    }

    public AttributeIdentifier getActionGpIden() {
        return this.actionGroupIden;
    }

    public EntityAttributes getIssuer() {
        return this.issuer;
    }

    public int getInitializationCount() {
        return initCount;
    }


}
