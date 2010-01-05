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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class TestAttributes {

    URI attrId = null;
    URI stringDatatype = null;

    @BeforeClass
    public void setup() throws Exception {
        this.attrId = new URI("urn:oasis:names:tc:xacml:1.0:subject:subject-id");
        this.stringDatatype = new URI("http://www.w3.org/2001/XMLSchema#string");
    }

    @Test
    public void testAttributes() throws Exception {
        attributeTest(false);
        attributeTest(true);
    }

    public void attributeTest(boolean identity) throws Exception {

        //just for sanity
        boolean expOccured = false;
        try {
            AttributeIdentifier attr1Iden =
                    new AttributeIdentifier(null, stringDatatype, identity);
        } catch (IllegalArgumentException exp) {
            expOccured = true;
        }
        assert (expOccured);

        expOccured = false;
        try {
            AttributeIdentifier attr1Iden =
                    new AttributeIdentifier(attrId, null, identity);
        } catch (IllegalArgumentException exp) {
            expOccured = true;
        }
        assert (expOccured);

        AttributeIdentifier attr1Iden = null;
        if (identity) {
            attr1Iden = new AttributeIdentifier(attrId, stringDatatype,
                    identity);
        } else {
            attr1Iden = new AttributeIdentifier(attrId, stringDatatype);
        }

        Attribute attr1 = null;

        expOccured = false;
        try {
            attr1 = new Attribute(attr1Iden, null, null, null);
        } catch (IllegalArgumentException exp) {
            expOccured = true;
        }
        assert (expOccured);

        Calendar now = Calendar.getInstance();
        Calendar later = Calendar.getInstance();
        later.add(Calendar.MINUTE, 1);

        expOccured = false;
        try {
            attr1 = new Attribute(attr1Iden, null, later, now);
        } catch (IllegalArgumentException exp) {
            expOccured = true;
        }
        assert (expOccured);

        HashSet hset = new HashSet();
        hset.add("dummy");
        AttributeIdentifier attrIden =
                new AttributeIdentifier(attrId, stringDatatype, true);
        attr1 = new Attribute(attrIden, null, now, later, hset);

        // create a identity attribute to create entity attribute for
        // issuer
        IdentityAttributeCollection col = new IdentityAttributeCollection();
        col.add(attr1);
        EntityAttributes issuer = new EntityAttributes(col, null, null);

        hset = new HashSet();
        hset.add("newDummy");
        attr1 = new Attribute(attrIden, null, now, later, hset);
        col = new IdentityAttributeCollection();
        col.add(attr1);
        EntityAttributes badIssuer = new EntityAttributes(col, null, null);

        attr1 = new Attribute(attr1Iden, issuer, now, later);

        // assert identity attribute
        assert (attr1.isIdentityAttribute() == identity);

        // add values
        attr1.addAttributeValue("value0");
        HashSet vec1 = new HashSet();
        vec1.add("value1");
        vec1.add("value2");
        attr1.setAttributeValueSet(vec1);

        // attr2 without values
        Attribute attr2 = new Attribute(attr1Iden, issuer, now, null);
        assert (!attr1.isSameAttribute(attr2));

        HashSet vec = new HashSet();
        vec.add("value1");

        // attr2 with value1
        attr2 = new Attribute(attr1Iden, issuer, now, later, vec);
        assert (attr1.isSameAttribute(attr2));

        // bad issuer
        attr2 = new Attribute(new AttributeIdentifier(attrId, stringDatatype),
                badIssuer, now, null, vec);
        assert (!attr1.isSameAttribute(attr2));

        // bad data type
        URI notStr =
                new URI("http://www.w3.org/2001/XMLSchema#notstring");
        attr2 = new Attribute(new AttributeIdentifier(attrId, notStr), issuer,
                now, null, vec);
        assert (!attr1.isSameAttribute(attr2));

        // bad id
        URI notAttrId =
                new URI("urn:oasis:names:tc:xacml:1.0:subject:notsubject-id");
        attr2 = new Attribute(new AttributeIdentifier(notAttrId,
                stringDatatype), issuer,
                now, null, vec);
        assert (!attr1.isSameAttribute(attr2));

        vec = new HashSet();
        vec.add("value4");
        vec.add("value1");
        attr2 = new Attribute(new AttributeIdentifier(attrId, stringDatatype,
                identity), issuer, now,
                null, vec);
        assert (attr1.isSameAttribute(attr2));

        // check number of values
        Set values = attr2.getAttributeValueSet();
        assert (values.size() == 2);

        // add diff value
        attr2.addAttributeValue("value401");
        assert (values.size() == 3);

        // add same value
        attr2.addAttributeValue("value4");
        assert (values.size() == 3);

        now = Calendar.getInstance();
        later = Calendar.getInstance();
        later.add(Calendar.MINUTE, 10);
        Calendar before = Calendar.getInstance();
        before.add(Calendar.MINUTE, -10);

        // test merge
        Attribute mergeAttr1 =
                new Attribute(new AttributeIdentifier(attrId, stringDatatype,
                        identity), issuer, before,
                        now);
        mergeAttr1.addAttributeValue("val1");

        Attribute mergeAttr2 =
                new Attribute(new AttributeIdentifier(attrId, stringDatatype,
                        identity), issuer, now,
                        later);
        mergeAttr2.addAttributeValue("val2");

        mergeAttr1.merge(mergeAttr2);

        Calendar validFrom = mergeAttr1.getValidFrom();
        Calendar validTill = mergeAttr1.getValidTill();
        assert (now.equals(validFrom));
        assert (now.equals(validTill));

        Set mergeVal = mergeAttr1.getAttributeValueSet();
        Iterator it = mergeVal.iterator();
        if (it.hasNext()) {
            assert ("val1".equals(it.next()));
        }

        if (it.hasNext()) {
            assert ("val2".equals(it.next()));
        }


        mergeAttr1 =
                new Attribute(new AttributeIdentifier(attrId, stringDatatype,
                        identity), issuer, now,
                        later);
        mergeAttr1.addAttributeValue("val1");

        Calendar later2 = later;
        later2.add(Calendar.MINUTE, 10);
        mergeAttr2 =
                new Attribute(new AttributeIdentifier(attrId, stringDatatype,
                        identity), issuer, before,
                        later2);
        mergeAttr2.addAttributeValue("val2");

        mergeAttr1.merge(mergeAttr2);

        validFrom = mergeAttr1.getValidFrom();
        validTill = mergeAttr1.getValidTill();

        assert (now.equals(validFrom));
        assert (later.equals(validTill));

    }
}
