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
import java.util.Set;

import org.testng.annotations.Test;

public class TestEntityAttributes {

    String issuer = "dummy";
    Calendar now = Calendar.getInstance();

    @Test
    public void testAttributeCollection() throws Exception {

        // try entity will null identity attribute
        boolean exp = false;
        try {
            EntityAttributes entAttr = new EntityAttributes(null);
        } catch (IllegalArgumentException ilArgExp) {
            exp = true;
        }
        assert (exp);

        URI stringDatatype =
                new URI("http://www.w3.org/2001/XMLSchema#string");
        URI subjectId =
                new URI("urn:oasis:names:tc:xacml:1.0:subject:subject-id");
        URI idNumber =
                new URI("urn:oasis:names:tc:xacml:1.0:unquie:idNumber");
        URI intDatatype =
                new URI("http://www.w3.org/2001/XMLSchema#int");
        URI tokenId =
                new URI("urn:oasis:names:tc:xacml:1.0:token:token-id");
        URI roleId =
                new URI("urn:oasis:names:tc:xacml:1.0:role:role-id");
        URI usernameId =
                new URI("urn:oasis:names:tc:xacml:1.0:username:username-id");

        // Entity 1
        // identity attribute 1
        String subjectVal1 = "/DN/dummy subject/dn";
        String subjectVal2 = "value2";
        HashSet hashSet = new HashSet();
        hashSet.add(subjectVal1);
        hashSet.add(subjectVal2);

        AttributeIdentifier subjectIden =
                new AttributeIdentifier(subjectId, stringDatatype, true);
        Attribute issuerAttr = new Attribute(subjectIden, null, now, null,
                hashSet);
        IdentityAttributeCollection col = new IdentityAttributeCollection();
        col.add(issuerAttr);
        EntityAttributes issuer = new EntityAttributes(col, null, null);

        // isssuer 1, hashSet with subject val
        Attribute ent1idenAttr1 = new Attribute(subjectIden, issuer, now, null,
                hashSet);

        HashSet hashSet1 = new HashSet();
        hashSet1.add(new Integer(10000));

        // issuer 1, hashSet with integer val
        Attribute ent1idenAttr2 =
                new Attribute(new AttributeIdentifier(idNumber, intDatatype,
                        true), issuer, now, null,
                        hashSet1);

        // Entity 1
        IdentityAttributeCollection ent1IdenCol1 =
                new IdentityAttributeCollection();
        ent1IdenCol1.add(ent1idenAttr1);
        ent1IdenCol1.add(ent1idenAttr2);
        EntityAttributes ent1 = new EntityAttributes(ent1IdenCol1);

        Integer tokenIdenVal1 = new Integer("123456");
        HashSet hashSet2 = new HashSet();
        hashSet2.add(tokenIdenVal1);

        // issuer1, token value (identity attribute)
        AttributeIdentifier tokenIden =
                new AttributeIdentifier(tokenId, intDatatype, true);
        Attribute ent2idenAttr1 = new Attribute(tokenIden, issuer, now, null,
                hashSet2);

        IdentityAttributeCollection ent2IdenCol1 =
                new IdentityAttributeCollection();
        ent2IdenCol1.add(ent2idenAttr1);

        // regular attribute
        String roleIdenVal1 = "administrator";
        AttributeIdentifier roleIden =
                new AttributeIdentifier(roleId, stringDatatype, false);
        Attribute ent2Attr1 = new Attribute(roleIden, issuer, now, null);
        ent2Attr1.addAttributeValue(roleIdenVal1);

        Attribute ent2Attr2 =
                new Attribute(new AttributeIdentifier(usernameId, stringDatatype,
                        false), issuer, now, null);
        ent2Attr2.addAttributeValue("globus");
        ent2Attr2.addAttributeValue("abcd");

        AttributeCollection ent2AttrCol = new AttributeCollection();
        ent2AttrCol.add(ent2Attr1);
        ent2AttrCol.add(ent2Attr2);

        // Entity 2
        EntityAttributes ent2 =
                new EntityAttributes(ent2IdenCol1, ent2AttrCol);

        // not same entity
        assert (!ent1.isSameEntity(ent2));

        // Third entity that has subject dn
        String subjectVal3 = "newMergedValue";
        Attribute ent3idenAttr1 =
                new Attribute(new AttributeIdentifier(subjectId, stringDatatype,
                        true), issuer, now, null);
        ent3idenAttr1.addAttributeValue(subjectVal1);
        ent3idenAttr1.addAttributeValue(subjectVal3);
        IdentityAttributeCollection ent3IdenCol =
                new IdentityAttributeCollection();
        ent3IdenCol.add(ent3idenAttr1);

        String roleIdenVal2 = "committer";
        Attribute ent3Attr1 =
                new Attribute(new AttributeIdentifier(roleId, stringDatatype,
                        false), issuer, now, null);
        ent3Attr1.addAttributeValue(roleIdenVal1);
        ent3Attr1.addAttributeValue(roleIdenVal2);
        AttributeCollection ent3AttrCol = new AttributeCollection();
        ent3AttrCol.add(ent3Attr1);

        HashSet ent3NativeAttr = new HashSet();
        ent3NativeAttr.add("foo");
        HashSet principals = new HashSet();
        principals.add("Some subject DN maybe");
        ent3NativeAttr.add(principals);

        // Entity 3
        EntityAttributes ent3 = new EntityAttributes(ent3IdenCol, ent3AttrCol,
                ent3NativeAttr);

        // ent 3 is same as ent1
        assert (ent1.isSameEntity(ent3));

        // merge
        ent1.mergeEntities(ent3);

        // Check IdentityAttributeCollection
        IdentityAttributeCollection retIdenAttrCol =
                ent1.getIdentityAttributes();
        // get attribute adn check new value was added
        Attribute attr = retIdenAttrCol.getAttribute(subjectIden, issuer);
        assert (attr != null);
        Set attrValue = attr.getAttributeValueSet();
        assert (attrValue != null);
        // three values
        assert (attrValue.size() == 3);
        // assert values
        assert (attrValue.contains(subjectVal1));
        assert (attrValue.contains(subjectVal2));
        assert (attrValue.contains(subjectVal3));

        // Check AttributeCollection
        AttributeCollection retAttrCol = ent1.getAttributes();
        assert (retAttrCol != null);
        assert (retAttrCol.equals(ent3AttrCol));

        // ent3 not same as ent2
        assert (!ent2.isSameEntity(ent3));

        // add token identity attribute
        Integer tokenIdenVal2 = new Integer("123098");
        Attribute ent3IdenAttr2 = new Attribute(tokenIden, issuer, now, null);
        ent3IdenAttr2.addAttributeValue(tokenIdenVal1);
        ent3IdenAttr2.addAttributeValue(tokenIdenVal2);
        ent3IdenCol = new IdentityAttributeCollection();
        ent3IdenCol.add(ent3IdenAttr2);

        ent3.addIdentityAttributes(ent3IdenCol);

        // ent3 now matches ent2
        assert (ent2.isSameEntity(ent3));

        // check that native attributes are null
        assert (ent2.getNativeAttributes() == null);

        // merge
        ent2.mergeEntities(ent3);

        // Check IdentityAttributeCollection
        retIdenAttrCol = ent2.getIdentityAttributes();
        assert (retIdenAttrCol != null);
        // get attribute adn check new value was added
        attr = retIdenAttrCol.getAttribute(tokenIden, issuer);
        attrValue = attr.getAttributeValueSet();
        assert (attrValue != null);
        // two values
        assert (attrValue.size() == 2);
        // assert values
        assert (attrValue.contains(tokenIdenVal1));
        assert (attrValue.contains(tokenIdenVal2));

        // Check AttributeCollection
        retAttrCol = ent2.getAttributes();
        assert (retAttrCol != null);
        attr = retAttrCol.getAttribute(roleIden, issuer);
        assert (retAttrCol != null);
        attrValue = attr.getAttributeValueSet();
        assert (attrValue != null);
        // two roles
        assert (attrValue.size() == 2);
        assert (attrValue.contains(roleIdenVal1));
        assert (attrValue.contains(roleIdenVal2));

        // Check native attributes
        Set retNativeAttr = ent2.getNativeAttributes();
        assert (retNativeAttr != null);
        assert (retNativeAttr.size() == 2);
        assert (retNativeAttr.contains(principals));
    }
}
