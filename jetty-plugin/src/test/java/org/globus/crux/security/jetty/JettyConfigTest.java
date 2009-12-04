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
package org.globus.crux.security.jetty;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.globus.crux.security.internal.JettyConfigService;
import org.globus.security.filestore.FileSigningPolicyStoreParameters;
import org.globus.security.jetty.GlobusSslSocketConnector;

import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.nio.SelectChannelConnector;
import org.testng.Assert;
import org.testng.TestNG;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
@Test
public class JettyConfigTest {
    private Server spy;
    Map<Class<? extends Connector>, Connector> connectors;

    @BeforeTest
    public void setup() throws Exception{
        connectors = new HashMap<Class<? extends Connector>, Connector>();
        spy = Mockito.spy(new Server());
        Mockito.doNothing().when(spy).start();
        Mockito.doNothing().when(spy).stop();
        Mockito.doReturn(false).when(spy).isRunning();
        Mockito.doAnswer(new Answer(){
            public Object answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                for(Object o: args){
                    if(o instanceof Connector){
                        Connector connector = (Connector) o;
                        connectors.put(connector.getClass(), connector);
                    }
                }
                return null;
            }
        }).when(spy).addConnector(Mockito.any(Connector.class));
    }

    public void testLoadProperties() throws Exception{
        JettyConfigService service = new JettyConfigService(spy);
        Properties properties = new Properties();
        properties.load(getClass().getResourceAsStream("/test-jetty.cfg"));
        service.updated(properties);
        Mockito.verify(spy).isRunning();
        Mockito.verify(spy, Mockito.times(2)).addConnector(Mockito.any(Connector.class));
        GlobusSslSocketConnector connector = (GlobusSslSocketConnector) connectors.get(GlobusSslSocketConnector.class);
        Assert.assertEquals(connector.getPort(), 55555);
        Assert.assertEquals(connector.getProtocol(), "TLS");
        Assert.assertEquals(connector.getProvider(), "Globus");
        Assert.assertTrue(connector.getSigningPolicyStoreParameters() instanceof FileSigningPolicyStoreParameters);
    }
}
