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

import org.testng.annotations.Test;

import java.util.Calendar;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

public class TestAttributeEngine {

    MockPIPImpl pip;
    Calendar now = Calendar.getInstance();
    EntityAttributes issuer;

    @Test
    public void test() throws Exception {
        MockEngine engine = new MockEngine("chain name");

        this.pip = new MockPIPImpl();
        this.pip.setupURI();
        this.issuer = this.pip.getIssuer();


        /*
        ChainConfig chainConfig = new MockChainConfig();
        chainConfig.setProperty("i0", "token", "T1");
        chainConfig.setProperty("i0", "name", "UA");
        chainConfig.setProperty("i0", "resource", "R2");
        chainConfig.setProperty("i0", "resGp", "G2");
        chainConfig.setProperty("i0", "action", "A2");
        chainConfig.setProperty("i0", "actionGp", "G2");
        */
        MockPIPImpl i0 = new MockPIPImpl();
        i0.setToken("T1");
        i0.setName("UA");
        i0.setResource("R2");
        i0.setResGroup("G2");
        i0.setAction("A2");
        i0.setActionGp("G2");
        engine.addPIP(new InterceptorConfig<MockPIPImpl>("i0", i0));

        /*
      chainConfig.setProperty("i1", "name", "UB");
      chainConfig.setProperty("i1", "resource", "R1");
      chainConfig.setProperty("i1", "resGp", "G1");
      chainConfig.setProperty("i1", "action", "A1");
      chainConfig.setProperty("i1", "actionGp", "G1");
        */

        MockPIPImpl i1 = new MockPIPImpl();
        i1.setName("UB");
        i1.setResource("R1");
        i1.setResGroup("G1");
        i1.setAction("A1");
        i1.setActionGp("G1");
        engine.addPIP(new InterceptorConfig<MockPIPImpl>("i1", i1));

        /*
        chainConfig.setProperty("i2", "token", "T1");
        chainConfig.setProperty("i2", "name", "UC");

        chainConfig.setProperty("i2", "resource", "R3");
        chainConfig.setProperty("i2", "action", "A4");
        chainConfig.setProperty("i2", "actionGp", "G1");
        */
        MockPIPImpl i2 = new MockPIPImpl();
        i2.setToken("T1");
        i2.setName("UC");
        i2.setResource("R3");
        i2.setAction("A4");
        i2.setActionGp("G1");
        engine.addPIP(new InterceptorConfig<MockPIPImpl>("i2", i2));

        /*
       chainConfig.setProperty("i3", "token", "T2");
       chainConfig.setProperty("i3", "name", "UD");
       chainConfig.setProperty("i3", "resource", "R3");
       chainConfig.setProperty("i3", "resGp", "G2");
       chainConfig.setProperty("i3", "action", "A3");
        */

        MockPIPImpl i3 = new MockPIPImpl();
        i3.setToken("T2");
        i3.setName("UD");
        i3.setResource("R3");
        i3.setResGroup("G2");
        i3.setAction("A3");
        engine.addPIP(new InterceptorConfig<MockPIPImpl>("i3", i3));

        // UA/T1 R2/G2 A2/G2
        // UB    R1/G1 A1/G1
        // UC/T1 R3    A4/G1
        // UD/T2 R3/G2 A3

        RequestEntities reqAttr = new RequestEntities();


        engine.engineInitialize("chain name");
        // since no PDPS are exercises, an issuer of null is okay here.
        engine.engineAuthorize(reqAttr, null);

        List subjectAttr = engine.engineGetSubjectAttrList();
        assertNotNull(subjectAttr);
        assertEquals(subjectAttr.size(), 3);

        EntityAttributes en1 = getUserAttribute(new String[]{"UA", "UC"}, new String[]{"T1"});
        EntityAttributes en2 = getUserAttribute(new String[]{"UB"}, null);
        EntityAttributes en3 = getUserAttribute(new String[]{"UD"}, new String[]{"T2"});

        int i = 0;
        for (Object next : subjectAttr) {
            EntityAttributes en = (EntityAttributes) next;
            if (en.isSameEntity(en1) || en.isSameEntity(en2) || en.isSameEntity(en3)) {
                i++;
                if (i == 3) {
                    break;
                }
            }
        }

        assertEquals(i, 3);

        List resourceAttr = engine.engineGetResourceAttrList();
        assertEquals(resourceAttr.size(), 3);

        en1 = getResourceAttribute(new String[]{"R2", "R3"}, new String[]{"G2"});
        en2 = getResourceAttribute(new String[]{"R3"}, null);
        en3 = getResourceAttribute(new String[]{"R1"}, new String[]{"G1"});

        i = 0;
        for (Object next : resourceAttr) {
            EntityAttributes en = (EntityAttributes) next;
            if (en.isSameEntity(en1)) {
                i++;
                if (i == 3) {
                    break;
                }
            } else if (en.isSameEntity(en2)) {
                i++;
                if (i == 3) {
                    break;
                }
            } else if (en.isSameEntity(en3)) {
                i++;
                if (i == 3) {
                    break;
                }
            }
        }

        assertEquals(i, 3);

        List actionAttr = engine.engineGetActionAttrList();
        assertEquals(actionAttr.size(), 3);

        en1 = getActionAttribute(new String[]{"A1", "A4"}, new String[]{"G1"});
        en2 = getActionAttribute(new String[]{"A3",}, null);
        en3 = getActionAttribute(new String[]{"A2",}, new String[]{"G2"});

        i = 0;
        for (Object next : actionAttr) {
            EntityAttributes en = (EntityAttributes) next;
            if (en.isSameEntity(en1)) {
                i++;
                if (i == 3) {
                    break;
                }
            } else if (en.isSameEntity(en2)) {
                i++;
                if (i == 3) {
                    break;
                }
            } else if (en.isSameEntity(en3)) {
                i++;
                if (i == 3) {
                    break;
                }
            }
        }

        assertEquals(i, 3);
    }

    private EntityAttributes getUserAttribute(String[] names, String[] token) {

        IdentityAttributeCollection col =
                new IdentityAttributeCollection();

        if (names != null) {
            Attribute attr1 = new Attribute(this.pip.getUserIden(), this.issuer, now, null);
            for (String name : names) {
                attr1.addAttributeValue(name);
            }
            col.add(attr1);
        }

        if (token != null) {
            Attribute attr2 = new Attribute(this.pip.getTokenIden(), this.issuer, now, null);
            for (String aToken : token) {
                attr2.addAttributeValue(aToken);
            }
            col.add(attr2);
        }

        return new EntityAttributes(col);
    }

    private EntityAttributes getResourceAttribute(String[] id, String[] gp) {

        IdentityAttributeCollection col = new IdentityAttributeCollection();

        if (id != null) {
            Attribute attr1 = new Attribute(this.pip.getResourceIden(), this.issuer, now, null);
            for (String anId : id) {
                attr1.addAttributeValue(anId);
            }
            col.add(attr1);
        }

        if (gp != null) {
            Attribute attr2 = new Attribute(this.pip.getResourceGpIden(), this.issuer, now, null);
            for (String aGp : gp) {
                attr2.addAttributeValue(aGp);
            }
            col.add(attr2);
        }

        return new EntityAttributes(col);
    }

    private EntityAttributes getActionAttribute(String[] id, String[] gp) {

        IdentityAttributeCollection col = new IdentityAttributeCollection();

        if (id != null) {
            Attribute attr1 = new Attribute(this.pip.getActionIden(), this.issuer, now, null);
            for (String anId : id) {
                attr1.addAttributeValue(anId);
            }
            col.add(attr1);
        }

        if (gp != null) {
            Attribute attr2 = new Attribute(this.pip.getActionGpIden(), this.issuer, now, null);
            for (String aGp : gp) {
                attr2.addAttributeValue(aGp);
            }
            col.add(attr2);
        }

        return new EntityAttributes(col);
    }

}
