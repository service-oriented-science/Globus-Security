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
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class MockPDPImpl implements PDPInterceptor {

    private int initCount = 0;

    String prefix = null;

    public static String OWNER = "container";

    private String issuer;
    private List<String> access;
    private List<String> admin;
    private List<String> denied;
    private IdentityAttributeCollection owner;
    private EntityAttributes requestAttrIssuer = null;

    private EntityAttributes decisionIssuer = null;

    private AttributeIdentifier attrIden = null;
    
    

    public MockPDPImpl() throws InitializeException {
		this.initialize();
	}

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

    public void initialize() throws InitializeException {

        initCount++;

        this.attrIden = getTestUserAttrIdentifier();
    }

    private void setupIssuer() {

        AttributeIdentifier attrIdentifier = new AttributeIdentifier(TestConstants.ISSUER_ID,
                TestConstants.STRING_DATATYPE_URI, true);
        Attribute attribute = new Attribute(attrIdentifier, null, Calendar.getInstance(), null);
        IdentityAttributeCollection identityAttributes = new IdentityAttributeCollection();
        identityAttributes.add(attribute);
        EntityAttributes issuer = new EntityAttributes(identityAttributes, null);

        Attribute issuerAttr = new Attribute(this.attrIden, issuer, Calendar.getInstance(), null);

        if (this.issuer == null) {
            throw new IllegalArgumentException("Issuer cannot be null ");
        }

        issuerAttr.addAttributeValue(this.issuer);
        IdentityAttributeCollection attrCol = new IdentityAttributeCollection();
        attrCol.add(issuerAttr);
        this.decisionIssuer = new EntityAttributes(attrCol);

        // if OWNER, add the owner's identity attributes set in the test
        if (this.issuer.equals(OWNER)) {
            this.decisionIssuer.addIdentityAttributes(this.owner);
        }

    }

    public Decision canAccess(RequestEntities requestEntities, NonRequestEntities nonReqAttr)
            throws AuthorizationException {

        setupIssuer();
        // get peer
        EntityAttributes entityAttr = requestEntities.getRequestor();
        IdentityAttributeCollection col = entityAttr.getIdentityAttributes();
        Iterator<Attribute<?>> iterator = col.getAttributes(this.attrIden).iterator();
        Attribute<?> attr;
        // Not dealing with multiple issuers of same attribute in this test case
        Set<?> peerValues = null;
        if (iterator.hasNext()) {
            attr = iterator.next();
            peerValues = attr.getAttributeValueSet();
        }
        return isPermitted(peerValues, entityAttr, true);
    }

    public Decision canAdminister(RequestEntities requestEntities,
                                  NonRequestEntities nonReqAttr)
            throws AuthorizationException {

        setupIssuer();
        // get peer
        EntityAttributes entityAttr = requestEntities.getRequestor();
        IdentityAttributeCollection col = entityAttr.getIdentityAttributes();
        Iterator<Attribute<?>> iterator = col.getAttributes(this.attrIden).iterator();
        Attribute<?> attr;
        // Not dealing with multiple issuers of same attribute in this test case
        Set<?> values = null;
        if (iterator.hasNext()) {
            attr = iterator.next();
            values = attr.getAttributeValueSet();
        }
        return isPermitted(values, entityAttr, false);
    }

    public void close() {
    }

    private Decision isPermitted(Set<?> peerSet, EntityAttributes peerEntity, boolean access) {

        Iterator<?> peer = peerSet.iterator();
        if (this.denied != null) {
            while (peer.hasNext()) {
                if (this.denied.contains(peer.next().toString())) {
                    return new Decision(this.decisionIssuer, peerEntity,
                            Decision.DENY, null, null);
                }
            }
        }

        peer = peerSet.iterator();
        if (access) {
            if (this.access != null) {
                while (peer.hasNext()) {
                    if (this.access.contains(peer.next().toString())) {
                        return new Decision(this.decisionIssuer, peerEntity,
                                Decision.PERMIT, null, null);
                    }
                }
            }
        } else if (this.admin != null) {
            while (peer.hasNext()) {
                if (this.admin.contains(peer.next().toString())) {
                    return new Decision(this.decisionIssuer, peerEntity, Decision.PERMIT, null, null);
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

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public List<String> getAccess() {
        return access;
    }

    public void setAccess(List<String> access) {
        this.access = access;
    }

    public List<String> getAdmin() {
        return admin;
    }

    public void setAdmin(List<String> admin) {
        this.admin = admin;
    }

    public List<String> getDenied() {
        return denied;
    }

    public void setDenied(List<String> denied) {
        this.denied = denied;
    }

    public EntityAttributes getRequestAttrIssuer() {
        return requestAttrIssuer;
    }

    public void setRequestAttrIssuer(EntityAttributes requestAttrIssuer) {
        this.requestAttrIssuer = requestAttrIssuer;
    }

    public IdentityAttributeCollection getOwner() {
        return owner;
    }

    public void setOwner(IdentityAttributeCollection owner) {
        this.owner = owner;
    }
}

