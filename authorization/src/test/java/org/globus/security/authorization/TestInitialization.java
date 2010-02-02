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

import java.util.List;

import static org.testng.Assert.*;

public class TestInitialization {

    @Test
    public void test() throws Exception {
        MockEngine engine = new MockEngine("chain name");

        // Bootstrap PIPs
        MockBootstrapPIP b0 = new MockBootstrapPIP();
        MockBootstrapPIP b1 = new MockBootstrapPIP();
        engine.addBootstrapPIP(new InterceptorConfig<MockBootstrapPIP>("b0", b0));
        engine.addBootstrapPIP(new InterceptorConfig<MockBootstrapPIP>("b0", b0));
        engine.addBootstrapPIP(new InterceptorConfig<MockBootstrapPIP>("b1", b1));
        engine.addBootstrapPIP(new InterceptorConfig<MockBootstrapPIP>("b0", b0));


        // PIPs
        engine.addPIP(new InterceptorConfig<MockPIPImpl>("p1", new MockPIPImpl()));
        engine.addPIP(new InterceptorConfig<MockPIPImpl>("p0", new MockPIPImpl()));
        engine.addPIP(new InterceptorConfig<MockPIPImpl>("p1", new MockPIPImpl()));
        engine.addPIP(new InterceptorConfig<MockPIPImpl>("p0", new MockPIPImpl()));
        engine.addPIP(new InterceptorConfig<MockPIPImpl>("p0", new MockPIPImpl()));

        // PDPs
        engine.addPDP(new InterceptorConfig<MockPDPImpl>("d1", new MockPDPImpl()));
        engine.addPDP(new InterceptorConfig<MockPDPImpl>("d0", new MockPDPImpl()));
        engine.addPDP(new InterceptorConfig<MockPDPImpl>("d1", new MockPDPImpl()));
        engine.addPDP(new InterceptorConfig<MockPDPImpl>("d0", new MockPDPImpl()));
        engine.addPDP(new InterceptorConfig<MockPDPImpl>("d2", new MockPDPImpl()));
        engine.addPDP(new InterceptorConfig<MockPDPImpl>("d0", new MockPDPImpl()));

        engine.engineInitialize("chain name");

        List<BootstrapPIP> bootstrapPIP = engine.getBootstrapPIPs();
        assertNotNull(bootstrapPIP);
        assertEquals(bootstrapPIP.size(), 4);
        assertTrue(bootstrapPIP.get(0) instanceof MockBootstrapPIP);
        assertEquals(bootstrapPIP.get(0), (bootstrapPIP.get(1)));
        assertEquals(bootstrapPIP.get(1), (bootstrapPIP.get(3)));
        assertEquals(((MockBootstrapPIP) bootstrapPIP.get(0)).getInitializationCount(), 1);
        assertFalse(bootstrapPIP.get(1).equals(bootstrapPIP.get(2)));
        assertEquals(((MockBootstrapPIP) bootstrapPIP.get(2)).getInitializationCount(), 1);
        assertTrue(bootstrapPIP.get(2) instanceof MockBootstrapPIP);
        assertFalse(bootstrapPIP.get(2).equals(bootstrapPIP.get(3)));

        List<PIPInterceptor> pipClass = engine.getPIPs();
        assertNotNull(pipClass);
        assertEquals(pipClass.size(), 5);
        assertTrue(pipClass.get(0) instanceof MockPIPImpl);
        assertEquals(pipClass.get(0), (pipClass.get(2)));
        assertEquals(((MockPIPImpl) pipClass.get(0)).getInitializationCount(), 1);
        assertEquals(pipClass.get(1), (pipClass.get(3)));
        assertEquals(pipClass.get(3), (pipClass.get(4)));
        assertEquals(((MockPIPImpl) pipClass.get(1)).getInitializationCount(), 1);
        assertEquals(((MockPIPImpl) pipClass.get(3)).getInitializationCount(), 1);
        assertEquals(((MockPIPImpl) pipClass.get(4)).getInitializationCount(), 1);

        List<PDPInterceptor> pdpClass = engine.getPDPs();
        assertNotNull(pdpClass);
        assertEquals(pdpClass.size(), 6);
        assertTrue(pdpClass.get(0) instanceof MockPDPImpl);
        assertEquals(pdpClass.get(0), (pdpClass.get(2)));
        assertEquals(((MockPDPImpl) pdpClass.get(0)).getInitializationCount(), 1);
        assertEquals(((MockPDPImpl) pdpClass.get(2)).getInitializationCount(), 1);
        assertTrue(pdpClass.get(1) instanceof MockPDPImpl);
        assertEquals(pdpClass.get(1), (pdpClass.get(3)));
        assertEquals(pdpClass.get(3), (pdpClass.get(5)));
        assertEquals(((MockPDPImpl) pdpClass.get(1)).getInitializationCount(), 1);
        assertEquals(((MockPDPImpl) pdpClass.get(3)).getInitializationCount(), 1);
        assertEquals(((MockPDPImpl) pdpClass.get(5)).getInitializationCount(), 1);
        assertTrue(pdpClass.get(4) instanceof MockPDPImpl);
        assertEquals(((MockPDPImpl) pdpClass.get(4)).getInitializationCount(), 1);
    }
}
