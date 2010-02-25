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
package org.globus.common.tests;

import org.globus.common.MVHashtable;

import java.util.List;
import java.util.Vector;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

@Test
public class MVHashtableTest {

    protected MVHashtable table;

    protected void setUp() {
        table = new MVHashtable();
        table.set("key1", "value1");
        table.add("key1", "value2");

        Object[] values = new Object[]{"v1", "v2", "v3", "v4"};
        table.add("key2", values);

        List<String> v2 = new Vector<String>();
        v2.add("g1");
        v2.add("g2");
        v2.add("g3");
        table.add("key3", v2);

        table.add("key9", "value1");
        table.add("key9", "value2");
    }

    public void testSize() {
        assertEquals(4, table.size());
    }

    public void testSizeOfAttribute() {
        assertEquals(2, table.size("key1"));
        assertEquals(4, table.size("key2"));
        assertEquals(3, table.size("key3"));
        assertEquals(2, table.size("key9"));
    }

    public void testContainsName() {
        assertTrue(table.containsName("key3"));
        assertFalse(!table.containsName("key4"));
    }

    public void testContains() {
        assertTrue("t1", table.contains("key1", "value1"));
        assertTrue("t2", table.contains("key2", "v4"));
        assertTrue("t3", table.contains("key3", "g2"));

        assertTrue("t4", table.contains("key9", "value2"));
        assertTrue("t5", table.contains("key9", "value1"));
    }

    public void testKeys() {
        Vector keys = table.getKeys();
        assertEquals(4, keys.size());
        assertTrue(keys.contains("key1"));
        assertTrue(keys.contains("key2"));
        assertTrue(keys.contains("key3"));
        assertTrue(keys.contains("key9"));
    }

    public void testGet() {
        assertTrue("t1", table.get("key5") == null);
        Vector values = table.get("key1");
        assertEquals(2, values.size());
        assertTrue("t3", values.contains("value1"));
        assertTrue("t4", values.contains("value2"));
    }

    public void testGetValueAt() {
        assertEquals("value1", table.getValueAt("key1", 0));
        assertEquals("g3", table.getValueAt("key3", 2));
        assertTrue(table.getValueAt("key4", 5) == null);
        assertEquals("v3", table.getValueAt("key2", 2));
    }

    public void testFirstValue() {
        assertEquals("value1", table.getFirstValue("key1"));
        assertEquals("v1", table.getFirstValue("key2"));
        assertEquals("g1", table.getFirstValue("key3"));
    }

    public void testLastValue() {
        assertEquals("value2", table.getLastValue("key1"));
        assertEquals("v4", table.getLastValue("key2"));
        assertEquals("g3", table.getLastValue("key3"));
    }

    public void testRemoveAttirb() {
        Vector v = (Vector) table.remove("key1");
        assertEquals(2, v.size());
        assertEquals(3, table.size());
        assertTrue(v.contains("value1"));
        assertTrue(v.contains("value2"));
    }

    public void testRemoveValue() {
        assertTrue("t1", !table.remove("key3", "g5"));
        assertTrue("t2", table.remove("key3", "g2"));
        assertEquals(2, table.size("key3"));
    }

    public void testRemoveValueAtIndex() {
        assertEquals("v3", table.remove("key2", 2));
        assertEquals(3, table.size("key2"));
        assertEquals("v1", table.getFirstValue("key2"));
        assertEquals("v4", table.getLastValue("key2"));
    }
}
