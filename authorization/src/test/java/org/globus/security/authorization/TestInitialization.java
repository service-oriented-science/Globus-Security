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

import org.testng.annotations.Test;

public class TestInitialization {

    @Test
    public void test() throws Exception {

        // Bootstrap PIPs
        InterceptorConfig[] bpips = new InterceptorConfig[4];
        bpips[0] = new InterceptorConfig("b0",
                MockBootstrapPIP.class.getName());
        bpips[1] = new InterceptorConfig("b0",
                MockBootstrapPIP.class.getName());
        bpips[2] = new InterceptorConfig("b1",
                MockBootstrapPIP.class.getName());
        bpips[3] = new InterceptorConfig("b0",
                MockBootstrapPIP.class.getName());

        // PIPs
        InterceptorConfig[] pips = new InterceptorConfig[5];
        pips[0] = new InterceptorConfig("p1", MockPIPImpl.class.getName());
        pips[1] = new InterceptorConfig("p0", MockPIPImpl.class.getName());
        pips[2] = new InterceptorConfig("p1", MockPIPImpl.class.getName());
        pips[3] = new InterceptorConfig("p0", MockPIPImpl.class.getName());
        pips[4] = new InterceptorConfig("p0", MockPIPImpl.class.getName());

        // PDPs
        InterceptorConfig[] pdps = new InterceptorConfig[6];
        pdps[0] = new InterceptorConfig("d1", MockPDPImpl.class.getName());
        pdps[1] = new InterceptorConfig("d0", MockPDPImpl.class.getName());
        pdps[2] = new InterceptorConfig("d1", MockPDPImpl.class.getName());
        pdps[3] = new InterceptorConfig("d0", MockPDPImpl.class.getName());
        pdps[4] = new InterceptorConfig("d2", MockPDPImpl.class.getName());
        pdps[5] = new InterceptorConfig("d0", MockPDPImpl.class.getName());

        AuthorizationConfig authzConfig = new AuthorizationConfig(bpips, pips,
                pdps);

        MockEngine engine = new MockEngine();
        engine.engineInitialize("chain name", authzConfig, null);

        BootstrapPIP[] bootstrapPIP = engine.getBootstrapPIPs();
        assert (bootstrapPIP != null);
        assert (bootstrapPIP.length == 4);
        assert (bootstrapPIP[0] instanceof MockBootstrapPIP);
        assert (bootstrapPIP[0].equals(bootstrapPIP[1]));
        assert (bootstrapPIP[1].equals(bootstrapPIP[3]));
        assert (((MockBootstrapPIP) bootstrapPIP[0]).getInitializationCount()
                == 1);
        assert (!bootstrapPIP[1].equals(bootstrapPIP[2]));
        assert (((MockBootstrapPIP) bootstrapPIP[2]).getInitializationCount()
                == 1);
        assert (bootstrapPIP[2] instanceof MockBootstrapPIP);
        assert (!bootstrapPIP[2].equals(bootstrapPIP[3]));

        PIPInterceptor[] pipClass = engine.getPIPs();
        assert (pipClass != null);
        assert (pipClass.length == 5);
        assert (pipClass[0] instanceof MockPIPImpl);
        assert (pipClass[0].equals(pipClass[2]));
        assert (((MockPIPImpl) pipClass[0]).getInitializationCount() == 1);
        assert (pipClass[1].equals(pipClass[3]));
        assert (pipClass[3].equals(pipClass[4]));
        assert (((MockPIPImpl) pipClass[1]).getInitializationCount() == 1);
        assert (((MockPIPImpl) pipClass[3]).getInitializationCount() == 1);
        assert (((MockPIPImpl) pipClass[4]).getInitializationCount() == 1);

        PDPInterceptor[] pdpClass = engine.getPDPs();
        assert (pdpClass != null);
        assert (pdpClass.length == 6);
        assert (pdpClass[0] instanceof MockPDPImpl);
        assert (pdpClass[0].equals(pdpClass[2]));
        assert (((MockPDPImpl) pdpClass[0]).getInitializationCount() == 1);
        assert (((MockPDPImpl) pdpClass[2]).getInitializationCount() == 1);
        assert (pdpClass[1] instanceof MockPDPImpl);
        assert (pdpClass[1].equals(pdpClass[3]));
        assert (pdpClass[3].equals(pdpClass[5]));
        assert (((MockPDPImpl) pdpClass[1]).getInitializationCount() == 1);
        assert (((MockPDPImpl) pdpClass[3]).getInitializationCount() == 1);
        assert (((MockPDPImpl) pdpClass[5]).getInitializationCount() == 1);
        assert (pdpClass[4] instanceof MockPDPImpl);
        assert (((MockPDPImpl) pdpClass[4]).getInitializationCount() == 1);
    }
}
