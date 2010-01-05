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

import java.net.URI;
import java.util.Calendar;
import java.util.Iterator;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;

public class MockPDPImpl implements PDPInterceptor {

    private int initCount = 0;

    ChainConfig chainConfig = null;
    String prefix = null;

    String ISSUER_CONFIG = "issuer";
    String ACCESS_CONFIG = "access";
    String ADMIN_CONFIG = "admin";
    String DENIED_CONFIG = "denied";
    String REQ_ISSUER = "reqIssuer";
    public static String OWNER = "container";

    EntityAttributes decisionIssuer = null;

    Vector allowed = null;
    Vector admin = null;
    Vector denied = null;

    AttributeIdentifier attrIden = null;
    EntityAttributes requestAttrIssuer = null;

    public static AttributeIdentifier getTestUserAttrIdentifier()
            throws InitializeException {

        URI uri;
        try {
            uri = new URI("urn:globus:4.0:test:user");
        } catch (Exception exp) {
            throw new InitializeException("bad URI", exp);
        }

        return getTestAttrIdentifier(uri);
    }

    public static AttributeIdentifier getTestActionAttrIdentifier()
            throws InitializeException {

        URI uri;
        try {
            uri = new URI("urn:globus:4.0:test:action");
        } catch (Exception exp) {
            throw new InitializeException("bad URI", exp);
        }

        return getTestAttrIdentifier(uri);
    }

    public static AttributeIdentifier getTestResourceAttrIdentifier()
            throws InitializeException {

        URI uri;
        try {
            uri = new URI("urn:globus:4.0:test:resource");
        } catch (Exception exp) {
            throw new InitializeException("bad URI", exp);
        }

        return getTestAttrIdentifier(uri);
    }

    private static AttributeIdentifier getTestAttrIdentifier(URI attributeURI)
            throws InitializeException {

        return new AttributeIdentifier(attributeURI,
                TestConstants.STRING_DATATYPE_URI,
                true);
    }

    public void initialize(String chainName, String prefix_,
                           ChainConfig config) throws InitializeException {

        initCount++;

        if (config == null) {
            return;
        }

        this.prefix = prefix_;
        this.chainConfig = config;

        String temp = (String) this.chainConfig.getProperty(this.prefix,
                ACCESS_CONFIG);
        if (temp != null) {
            this.allowed = new Vector();
            StringTokenizer strTok = new StringTokenizer(temp);
            while (strTok.hasMoreTokens()) {
                this.allowed.add(strTok.nextToken());
            }
        }

        temp = (String) this.chainConfig.getProperty(this.prefix, ADMIN_CONFIG);
        if (temp != null) {
            this.admin = new Vector();
            StringTokenizer strTok = new StringTokenizer(temp);
            while (strTok.hasMoreTokens()) {
                this.admin.add(strTok.nextToken());
            }
        }

        temp = (String) this.chainConfig.getProperty(this.prefix,
                DENIED_CONFIG);
        if (temp != null) {
            this.denied = new Vector();
            StringTokenizer strTok = new StringTokenizer(temp);
            while (strTok.hasMoreTokens()) {
                this.denied.add(strTok.nextToken());
            }
        }

        this.attrIden = getTestUserAttrIdentifier();

        this.requestAttrIssuer = (EntityAttributes) this.chainConfig.
                getProperty(this.prefix, REQ_ISSUER);
    }

    private void setupIssuer() {

        AttributeIdentifier attrIdentifier =
                new AttributeIdentifier(TestConstants.ISSUER_ID,
                        TestConstants.STRING_DATATYPE_URI,
                        true);
        Attribute attribute = new Attribute(attrIdentifier, null,
                Calendar.getInstance(), null);
        IdentityAttributeCollection identityAttributes =
                new IdentityAttributeCollection();
        identityAttributes.add(attribute);
        EntityAttributes issuer =
                new EntityAttributes(identityAttributes, null);

        Attribute issuerAttr = new Attribute(this.attrIden, issuer,
                Calendar.getInstance(), null);
        String issuerStr = (String) this.chainConfig.getProperty(this.prefix,
                ISSUER_CONFIG);

        if (issuerStr == null) {
            throw new IllegalArgumentException("Issuer cannot be null ");
        }

        issuerAttr.addAttributeValue(issuerStr);
        IdentityAttributeCollection attrCol =
                new IdentityAttributeCollection();
        attrCol.add(issuerAttr);
        this.decisionIssuer = new EntityAttributes(attrCol);

        // if OWNER, add the owner's identity attributes set in the test
        if (issuerStr.equals(OWNER)) {
            IdentityAttributeCollection attrs =
                    (IdentityAttributeCollection) this.chainConfig.
                            getProperty(this.prefix, OWNER);
            this.decisionIssuer.addIdentityAttributes(attrs);
        }

    }

    public Decision canAccess(RequestEntities requestEntities,
                              NonRequestEntities nonReqAttr)
            throws AuthorizationException {

        setupIssuer();
        // get peer
        EntityAttributes entityAttr = requestEntities.getRequestor();
        IdentityAttributeCollection col = entityAttr.getIdentityAttributes();
        Iterator iterator = col.getAttributes(this.attrIden).iterator();
        Attribute attr = null;
        // Not dealing with multiple issuers of same attribute in this test case
        if (iterator.hasNext()) {
            attr = (Attribute) iterator.next();
        }
        Set peerValues = attr.getAttributeValueSet();
        return isPermitted(peerValues, entityAttr, true);
    }

    public Decision canAdminister(RequestEntities requestEntities,
                                  NonRequestEntities nonReqAttr)
            throws AuthorizationException {

        setupIssuer();
        // get peer
        EntityAttributes entityAttr = requestEntities.getRequestor();
        IdentityAttributeCollection col = entityAttr.getIdentityAttributes();
        Iterator iterator = col.getAttributes(this.attrIden).iterator();
        Attribute attr = null;
        // Not dealing with multiple issuers of same attribute in this test case
        if (iterator.hasNext()) {
            attr = (Attribute) iterator.next();
        }
        Set values = attr.getAttributeValueSet();
        return isPermitted(values, entityAttr, false);
    }

    public void close() {
    }

    private Decision isPermitted(Set peerSet, EntityAttributes peerEntity,
                                 boolean access) {

        Iterator peer = peerSet.iterator();
        if (this.denied != null) {
            while (peer.hasNext()) {
                if (this.denied.contains(peer.next())) {
                    return new Decision(this.decisionIssuer, peerEntity,
                            Decision.DENY, null, null);
                }
            }
        }

        peer = peerSet.iterator();
        if (access) {
            if (this.allowed != null) {
                while (peer.hasNext()) {
                    if (this.allowed.contains(peer.next())) {
                        return new Decision(this.decisionIssuer, peerEntity,
                                Decision.PERMIT, null, null);
                    }
                }
            }
        } else if (this.admin != null) {
            while (peer.hasNext()) {
                if (this.admin.contains(peer.next())) {
                    return new Decision(this.decisionIssuer, peerEntity,
                            Decision.PERMIT, null, null);
                }
            }
        }

        return new Decision(this.decisionIssuer, peerEntity,
                Decision.NOT_APPLICABLE,
                null, null);
    }

    public int getInitializationCount() {
        return initCount;
    }
}
