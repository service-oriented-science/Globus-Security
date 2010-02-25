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
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import static junit.framework.Assert.assertTrue;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import org.testng.annotations.Test;

public class TestAttributeCollection {

	EntityAttributes issuer = null;
	EntityAttributes issuer1 = null;
	EntityAttributes issuer2 = null;
	URI stringDatatype = null;
	URI subjectId = null;
	URI tokenId = null;

	@Test
	public void testAttributeCollection() throws Exception {

		// identity attribute 1
		stringDatatype = new URI("http://www.w3.org/2001/XMLSchema#string");
		subjectId = new URI("urn:oasis:names:tc:xacml:1.0:subject:subject-id");
		tokenId = new URI("urn:org:globus:test:token-id");

		AttributeIdentifier attrIden = new AttributeIdentifier(subjectId, stringDatatype, true);

		// issuer 1
		Set<String> hset = new HashSet<String>();
		hset.add("dummy");
		Attribute<String> attr = new Attribute<String>(attrIden, null, Calendar.getInstance(), null, hset);
		IdentityAttributeCollection coll = new IdentityAttributeCollection();
		coll.add(attr);
		issuer = new EntityAttributes(coll, null, null);

		// same issure, different java object
		issuer2 = new EntityAttributes(coll, null, null);

		// another issuer
		hset = new HashSet<String>();
		hset.add("dummy123");
		attr = new Attribute<String>(attrIden, null, Calendar.getInstance(), null, hset);
		coll = new IdentityAttributeCollection();
		coll.add(attr);
		issuer1 = new EntityAttributes(coll, null, null);

		attrCollectionTest(false);
		attrCollectionTest(true);
	}

	@SuppressWarnings("unchecked")
	private void attrCollectionTest(boolean identity) throws Exception {

		Calendar now = Calendar.getInstance();
		Calendar before = Calendar.getInstance();
		before.add(Calendar.MINUTE, -3);
		Calendar after = Calendar.getInstance();
		after.add(Calendar.MINUTE, 3);

		AttributeIdentifier iden = new AttributeIdentifier(subjectId, stringDatatype, identity);
		Attribute<String> idenAttr1 = new Attribute<String>(iden, issuer, now, after);

		assert (idenAttr1.isIdentityAttribute() == identity);

		Set<String> vec1 = new HashSet<String>();
		vec1.add("/DN/dummy subject/dn");
		vec1.add("value2");
		idenAttr1.setAttributeValueSet(vec1);

		// identity attribute 2
		Attribute<String> idenAttr2 = new Attribute<String>(iden, issuer, before, after);

		assert (idenAttr2.isIdentityAttribute() == identity);

		Set<String> vec2 = new HashSet<String>();
		vec2.add("a");
		idenAttr2.setAttributeValueSet(vec2);

		// identity attribute 3
		Attribute<String> idenAttr3 = new Attribute<String>(iden, issuer1, before, after);
		assert (idenAttr3.isIdentityAttribute() == identity);
		Set<String> hashSet = new HashSet<String>();
		hashSet.add("different");
		idenAttr3.setAttributeValueSet(hashSet);

		// identity attribute 4
		Attribute<String> idenAttr4 = new Attribute<String>(iden, issuer, before, after);
		assert (idenAttr4.isIdentityAttribute() == identity);
		hashSet = new HashSet<String>();
		hashSet.add("b");
		idenAttr4.setAttributeValueSet(hashSet);

		// attribute collection
		AttributeCollection idenAttrCol1 = null;
		if (identity) {
			idenAttrCol1 = new IdentityAttributeCollection();
		} else {
			idenAttrCol1 = new AttributeCollection();
		}
		idenAttrCol1.add(idenAttr1);
		idenAttrCol1.add(idenAttr2);
		idenAttrCol1.add(idenAttr3);
		idenAttrCol1.add(idenAttr4);

		// attribute collection 2
		AttributeCollection idenAttrCol2 = null;
		if (identity) {
			idenAttrCol2 = new IdentityAttributeCollection();
		} else {
			idenAttrCol2 = new AttributeCollection();
		}
		idenAttrCol2.add(idenAttr2);

		assert (idenAttrCol1.isSameEntity(idenAttrCol2));

		// check if issuer is same, but different object
		Attribute<String> newAttr = new Attribute<String>(iden, issuer2, before, after);
		// attribute collection
		AttributeCollection newAttrCol1;
		if (identity) {
			newAttrCol1 = new IdentityAttributeCollection();
		} else {
			newAttrCol1 = new AttributeCollection();
		}
		newAttrCol1.add(newAttr);

		// compare collections. Should fail, since even one value does not match
		assert (!newAttrCol1.isSameEntity(idenAttrCol1));

		// add a value to attribute
		hashSet = new HashSet<String>();
		hashSet.add("a");
		hashSet.add("b");
		newAttr.setAttributeValueSet(hashSet);
		newAttrCol1.add(newAttr);

		// check if it things are merged
		assert (newAttrCol1.getAttributeIdentifiers().size() == 1);

		// now same entity test must work, since value match.
		assert (newAttrCol1.isSameEntity(idenAttrCol1));

		// check map size
		Map<EntityAttributes, Attribute<?>> map = newAttrCol1.getAttributeMap(iden);
		assertEquals(map.keySet().size(), 1);

		// Try with null issuer
		newAttr = new Attribute<String>(iden, null, before, after);
		newAttrCol1.add(newAttr);

		// should not be merged.
		assertEquals(newAttrCol1.getAttributeIdentifiers().size(), 1);
		map = newAttrCol1.getAttributeMap(iden);
		assertEquals(map.keySet().size(), 2);

		// Create another collection with null issuer and check isSameEntity
		AttributeIdentifier attrIden = new AttributeIdentifier(tokenId, stringDatatype, true);
		newAttr = new Attribute<String>(attrIden, null, before, after);
		newAttrCol1.add(newAttr);

		// should not be merged
		assertEquals(newAttrCol1.getAttributeIdentifiers().size(), 2);
		map = newAttrCol1.getAttributeMap(attrIden);
		assertEquals(map.keySet().size(), 1);

		// check with null issuer and same attribute identifier
		newAttr = new Attribute<String>(attrIden, null, before, after);
		newAttrCol1.add(newAttr);

		// should be merged
		assertEquals(newAttrCol1.getAttributeIdentifiers().size(), 2);
		map = newAttrCol1.getAttributeMap(attrIden);
		assertEquals(map.keySet().size(), 1);

		// add some attribute value and attempt merge
		newAttr = new Attribute<String>(attrIden, null, before, after);
		hashSet = new HashSet<String>();
		hashSet.add("Foobar");
		newAttr.setAttributeValueSet(hashSet);
		newAttrCol1.add(newAttr);
		assertEquals(map.keySet().size(), 1);

		// should be merged
		assertEquals(newAttrCol1.getAttributeIdentifiers().size(), 2);

		// test with some hash set content merge
		newAttr = new Attribute<String>(attrIden, null, before, after);
		hashSet = new HashSet<String>();
		hashSet.add("Foobar12");
		newAttr.setAttributeValueSet(hashSet);
		newAttrCol1.add(newAttr);

		// retrieve relevant values and check merge occurred
		map = newAttrCol1.getAttributeMap(attrIden);
		assertEquals(map.keySet().size(), 1);
		Attribute<?> retrievedNewAttr = map.get(null);
		Set<?> values = retrievedNewAttr.getAttributeValueSet();
		assertTrue(values != null);
		assertTrue(values.contains("Foobar"));
		assertTrue(values.contains("Foobar12"));

		// check collection.
		Collection<Attribute<?>> coll = idenAttrCol1.getAttributes(iden);
		assertTrue(coll != null);
		assertEquals(coll.size(), 2);
		List<String> val = new Vector<String>();
		for (Attribute<?> attr : coll) {
			val.addAll(((Attribute<String>) attr).getAttributeValueSet());
		}
		assertTrue(val.contains("/DN/dummy subject/dn"));
		assertTrue(val.contains("value2"));
		assertTrue(val.contains("a"));
		assertTrue(val.contains("b"));
		assertTrue(val.contains("different"));

		Attribute<String> retAttr1 = idenAttrCol1.getAttribute(iden, issuer);
		Set<String> val1 = retAttr1.getAttributeValueSet();
		assertTrue(val1.contains("/DN/dummy subject/dn"));
		assertTrue(val1.contains("value2"));
		assertTrue(val1.contains("a"));
		assertTrue(val1.contains("b"));
		assertFalse(val1.contains("different"));

		Attribute<String> retAttr2 = idenAttrCol1.getAttribute(iden, issuer1);
		val1 = retAttr2.getAttributeValueSet();
		assertFalse(val1.contains("/DN/dummy subject/dn"));
		assertFalse(val1.contains("value2"));
		assertFalse(val1.contains("a"));
		assertFalse(val1.contains("b"));
		assertTrue(val1.contains("different"));

		// try using HashMap
		Map<EntityAttributes, Attribute<?>> attrMap = idenAttrCol1.getAttributeMap(iden);
		assertNotNull(attrMap);
		Attribute<?> retAttr = attrMap.get(issuer);
		assertNotNull(retAttr);
		assertTrue(retAttr.isSameAttribute(retAttr1));
		retAttr = attrMap.get(issuer1);
		assertNotNull(retAttr);
		assertTrue(retAttr.isSameAttribute(retAttr2));

		// change value of identity attribute in attr collection 2
		Set<String> vec3 = new HashSet<String>();
		vec3.add("foo");
		idenAttr3 = new Attribute<String>(new AttributeIdentifier(subjectId, stringDatatype, identity), issuer, now,
				null, vec3);

		assertEquals(idenAttr3.isIdentityAttribute(), identity);

		AttributeCollection idenAttrCol3 = null;
		if (identity) {
			idenAttrCol3 = new IdentityAttributeCollection();
		} else {
			idenAttrCol3 = new AttributeCollection();
		}
		idenAttrCol3.add(idenAttr3);

		assertFalse(idenAttrCol1.isSameEntity(idenAttrCol3));

		// multiple value, with one match
		Set<String> vec4 = new HashSet<String>();
		vec4.add("a");
		vec4.add("random");
		idenAttr4 = new Attribute<String>(new AttributeIdentifier(subjectId, stringDatatype, identity), issuer, before,
				now, vec4);

		assertEquals(idenAttr4.isIdentityAttribute(), identity);

		AttributeCollection idenAttrCol4 = null;
		if (identity) {
			idenAttrCol4 = new IdentityAttributeCollection();
		} else {
			idenAttrCol4 = new AttributeCollection();
		}
		idenAttrCol4.add(idenAttr4);

		assertTrue(idenAttrCol2.isSameEntity(idenAttrCol4));
	}
}
