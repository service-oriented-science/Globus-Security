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

import java.beans.BeanInfo;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.nio.SelectChannelConnector;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedService;
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
    private static final String CONNECTOR_PREFIX = "org.globus.jetty.connector";
    private Map<String, Connector> connectorMap = new HashMap<String, Connector>();
    private Map<String, Object> propertyMap = new HashMap<String, Object>();

    public JettyConfigService(Server server) throws Exception {
        log.info("creating jetty config");
        this.jettyServer = server;
        SelectChannelConnector connector = new SelectChannelConnector();
        connector.setPort(8080);
        server.addConnector(connector);
        server.start();
    }

    public void updated(Dictionary dictionary) throws ConfigurationException {
        String key = null;
        try {
            if (jettyServer.isRunning()) {
                jettyServer.stop();
            }
            log.warn("updating config");
            log.warn(Integer.toString(dictionary.size()));
            Enumeration keys = dictionary.keys();
            while (keys.hasMoreElements()) {
                key = keys.nextElement().toString();
                if (key.startsWith(CONNECTOR_PREFIX)) {
                    String name = key.substring(CONNECTOR_PREFIX.length());
                    String[] contents = name.split(".");
                    if (contents.length == 1) {
                        String connectorName = contents[0];
                        Class connectorClass = Class.forName(dictionary.get(key).toString());
                        connectorMap.put(connectorName, (Connector) connectorClass.newInstance());
                    } else {
                        Connector connector = connectorMap.get(contents[0]);
                        BeanInfo info = Introspector.getBeanInfo(connector.getClass());
                        if (contents.length == 2) {
                            String propName = contents[1];
                            Object value = dictionary.get(key);
                            for (PropertyDescriptor descriptor : info.getPropertyDescriptors()) {
                                if (propName.equals(descriptor.getName())) {
                                    Class<?> propType = descriptor.getPropertyType();
                                    Object o = convertArg(value.toString(), propType);
                                    descriptor.getWriteMethod().invoke(connector, o);
                                }
                            }
                            info.getBeanDescriptor().setValue(propName, value);
                        }
                    }

                }
                log.warn(keys.nextElement().toString());
            }
            jettyServer.start();
        } catch (Exception e) {
            throw new ConfigurationException(key, e.getLocalizedMessage(), e);
        }
    }

    Object convertArg(String val, Class type) {
        if (val == null)
            return null;

        String v = val.trim();
        if (String.class.isAssignableFrom(type)) {
            return val;
        } else if (Integer.TYPE.isAssignableFrom(type)) {
            return new Integer(v);
        } else if (Long.TYPE.isAssignableFrom(type)) {
            return new Long(v);
        } else if (Boolean.TYPE.isAssignableFrom(type)) {
            if ("true".equalsIgnoreCase(v)) {
                return Boolean.TRUE;
            } else if ("false".equalsIgnoreCase(v)) {
                return Boolean.FALSE;
            }
        }
        return null;
    }

}
