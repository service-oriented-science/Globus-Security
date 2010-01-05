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
import java.util.List;

import org.testng.annotations.Test;

public class TestAttributeEngine {

    MockPIPImpl pip;
    Calendar now = Calendar.getInstance();
    EntityAttributes issuer;

    @Test
    public void test() throws Exception {

        this.pip = new MockPIPImpl();
        this.pip.setupURI();
        this.issuer = this.pip.getIssuer();

        InterceptorConfig[] pips = new InterceptorConfig[4];
        pips[0] = new InterceptorConfig("i0", MockPIPImpl.class.getName());
        pips[1] = new InterceptorConfig("i1", MockPIPImpl.class.getName());
        pips[2] = new InterceptorConfig("i2", MockPIPImpl.class.getName());
        pips[3] = new InterceptorConfig("i3", MockPIPImpl.class.getName());
        pips[3] = new InterceptorConfig("i3", MockPIPImpl.class.getName());
        AuthorizationConfig authzConfig = new AuthorizationConfig(null, pips,
                null);

        // UA/T1 R2/G2 A2/G2
        // UB    R1/G1 A1/G1
        // UC/T1 R3    A4/G1
        // UD/T2 R3/G2 A3
        ChainConfig chainConfig = new MockChainConfig();
        chainConfig.setProperty("i0", "token", "T1");
        chainConfig.setProperty("i0", "name", "UA");

        chainConfig.setProperty("i0", "resource", "R2");
        chainConfig.setProperty("i0", "resGp", "G2");
        chainConfig.setProperty("i0", "action", "A2");
        chainConfig.setProperty("i0", "actionGp", "G2");


        chainConfig.setProperty("i1", "name", "UB");
        chainConfig.setProperty("i1", "resource", "R1");
        chainConfig.setProperty("i1", "resGp", "G1");
        chainConfig.setProperty("i1", "action", "A1");
        chainConfig.setProperty("i1", "actionGp", "G1");

        chainConfig.setProperty("i2", "token", "T1");
        chainConfig.setProperty("i2", "name", "UC");

        chainConfig.setProperty("i2", "resource", "R3");
        chainConfig.setProperty("i2", "action", "A4");
        chainConfig.setProperty("i2", "actionGp", "G1");


        chainConfig.setProperty("i3", "token", "T2");
        chainConfig.setProperty("i3", "name", "UD");
        chainConfig.setProperty("i3", "resource", "R3");
        chainConfig.setProperty("i3", "resGp", "G2");
        chainConfig.setProperty("i3", "action", "A3");

        RequestEntities reqAttr = new RequestEntities();
        MockEngine engine = new MockEngine();
        engine.engineInitialize("chain name", authzConfig, chainConfig);
        // since no PDPS are exercises, an issuer of null is okay here.
        Decision decision = engine.engineAuthorize(reqAttr, null);

        List subjectAttr = engine.engineGetSubjectAttrList();
        assert (subjectAttr != null);
        assert (subjectAttr.size() == 3);

        EntityAttributes en1 = getUserAttribute(new String[]{"UA", "UC"},
                new String[]{"T1"});
        EntityAttributes en2 = getUserAttribute(new String[]{"UB"}, null);
        EntityAttributes en3 =
                getUserAttribute(new String[]{"UD"}, new String[]{"T2"});

        java.util.Iterator it = subjectAttr.iterator();
        int i = 0;
        while (it.hasNext()) {
            EntityAttributes en = (EntityAttributes) it.next();
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

        assert (i == 3);

        List resourceAttr = engine.engineGetResourceAttrList();
        assert (resourceAttr.size() == 3);

        en1 = getResourceAttribute(new String[]{"R2", "R3"},
                new String[]{"G2"});
        en2 = getResourceAttribute(new String[]{"R3",}, null);
        en3 =
                getResourceAttribute(new String[]{"R1",}, new String[]{"G1"});

        it = resourceAttr.iterator();
        i = 0;
        while (it.hasNext()) {
            EntityAttributes en = (EntityAttributes) it.next();
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

        assert (i == 3);

        List actionAttr = engine.engineGetActionAttrList();
        assert (actionAttr.size() == 3);

        en1 = getActionAttribute(new String[]{"A1", "A4"},
                new String[]{"G1"});
        en2 = getActionAttribute(new String[]{"A3",}, null);
        en3 =
                getActionAttribute(new String[]{"A2",}, new String[]{"G2"});

        it = actionAttr.iterator();
        i = 0;
        while (it.hasNext()) {
            EntityAttributes en = (EntityAttributes) it.next();
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

        assert (i == 3);
    }

    private EntityAttributes getUserAttribute(String[] names, String[] token) {

        IdentityAttributeCollection col =
                new IdentityAttributeCollection();

        if (names != null) {
            Attribute attr1 = new Attribute(this.pip.getUserIden(),
                    this.issuer, now, null);
            for (int i = 0; i < names.length; i++) {
                attr1.addAttributeValue(names[i]);
            }
            col.add(attr1);
        }

        if (token != null) {
            Attribute attr2 = new Attribute(this.pip.getTokenIden(),
                    this.issuer, now, null);
            for (int i = 0; i < token.length; i++) {
                attr2.addAttributeValue(token[i]);
            }
            col.add(attr2);
        }

        return new EntityAttributes(col);
    }

    private EntityAttributes getResourceAttribute(String[] id, String[] gp) {

        IdentityAttributeCollection col =
                new IdentityAttributeCollection();

        if (id != null) {
            Attribute attr1 = new Attribute(this.pip.getResourceIden(),
                    this.issuer, now, null);
            for (int i = 0; i < id.length; i++) {
                attr1.addAttributeValue(id[i]);
            }
            col.add(attr1);
        }

        if (gp != null) {
            Attribute attr2 = new Attribute(this.pip.getResourceGpIden(),
                    this.issuer, now, null);
            for (int i = 0; i < gp.length; i++) {
                attr2.addAttributeValue(gp[i]);
            }
            col.add(attr2);
        }

        return new EntityAttributes(col);
    }

    private EntityAttributes getActionAttribute(String[] id, String[] gp) {

        IdentityAttributeCollection col =
                new IdentityAttributeCollection();

        if (id != null) {
            Attribute attr1 = new Attribute(this.pip.getActionIden(),
                    this.issuer, now, null);
            for (int i = 0; i < id.length; i++) {
                attr1.addAttributeValue(id[i]);
            }
            col.add(attr1);
        }

        if (gp != null) {
            Attribute attr2 = new Attribute(this.pip.getActionGpIden(),
                    this.issuer, now, null);
            for (int i = 0; i < gp.length; i++) {
                attr2.addAttributeValue(gp[i]);
            }
            col.add(attr2);
        }

        return new EntityAttributes(col);
    }

}
