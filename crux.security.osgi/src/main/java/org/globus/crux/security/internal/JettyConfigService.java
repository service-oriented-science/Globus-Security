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
package org.globus.crux.security.internal;

import java.util.Dictionary;

import org.mortbay.jetty.Server;
import org.mortbay.jetty.nio.SelectChannelConnector;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedService;
import org.osgi.service.cm.ManagedServiceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class JettyConfigService implements ManagedService {
    private Server jettyServer;
    Logger log = LoggerFactory.getLogger(getClass());

    public JettyConfigService(Server server) throws Exception {
        this.jettyServer = server;
        SelectChannelConnector connector = new SelectChannelConnector();
        connector.setPort(8080);
        server.addConnector(connector);
        server.start();
    }

    public JettyConfigService(Server server, Dictionary dictionary) throws ConfigurationException{
        this.jettyServer = server;
        updated(dictionary);
    }

    public void updated(Dictionary dictionary) throws ConfigurationException {
        log.warn("updating config");
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }
}
