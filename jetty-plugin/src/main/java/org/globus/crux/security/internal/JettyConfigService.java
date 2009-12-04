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
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Server;
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
    private static final String CONNECTOR_PREFIX = "org.globus.jetty.connector.";
    private Map<String, Connector> connectorMap = new HashMap<String, Connector>();
    private Map<String, Object> propertyMap = new HashMap<String, Object>();

    public JettyConfigService(Server server) throws Exception {
        log.info("creating jetty config");
        this.jettyServer = server;
//        SelectChannelConnector connector = new SelectChannelConnector();
//        connector.setPort(8080);
//        server.addConnector(connector);
//        server.start();
    }

    public void updated(Dictionary dictionary) throws ConfigurationException {
        String key = null;
        try {
            if (jettyServer.isRunning()) {
                jettyServer.stop();
            }
            log.debug("updating config");
            Enumeration keys = dictionary.keys();
            while (keys.hasMoreElements()) {
                key = keys.nextElement().toString();
                if (key.startsWith(CONNECTOR_PREFIX)) {
                    String name = key.substring(CONNECTOR_PREFIX.length());
                    String[] contents;
                    if (name.indexOf(".") >= 0) {
                        contents = name.split("\\.");
                    } else {
                        contents = new String[]{name};
                    }
                    String currentName = CONNECTOR_PREFIX +  contents[0];
                    Object parent = getConnector(currentName, dictionary);
                    for(int i = 1 ; i < contents.length ; i++){
                        currentName = currentName + "." + contents[i];
                        parent = getProperty(parent, currentName, dictionary);
                    }
                }
                log.debug(key);
            }
            jettyServer.start();
        } catch (Exception e) {
            throw new ConfigurationException(key, e.getLocalizedMessage(), e);
        }
    }

    private  Connector getConnector(String connectorName, Dictionary dictionary) throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        Connector conn = connectorMap.get(connectorName);
        if (conn == null) {
            Class connectorClass = Class.forName(dictionary.get(connectorName).toString());
            conn = (Connector) connectorClass.newInstance();
            connectorMap.put(connectorName, conn);
            this.jettyServer.addConnector(conn);
        }
        return conn;
    }

    Map<String, Object> propertyCache = new HashMap<String, Object>();
    Map<Class<?>, BeanInfo> beanInfoCache = new HashMap<Class<?>, BeanInfo>();

    private PropertyDescriptor getDescriptor(BeanInfo info, String propName) {
        propName = propName.substring(propName.lastIndexOf(".") + 1);
        for (PropertyDescriptor desc : info.getPropertyDescriptors()) {
            if (desc.getName().equals(propName)) {
                return desc;
            }
        }
        return null;
    }

    private Object getProperty(Object parent, String propName, Dictionary dict) throws ClassNotFoundException, IllegalAccessException, InstantiationException, IntrospectionException, InvocationTargetException {
        Object o = propertyCache.get(propName);
        BeanInfo info = getBeanInfo(parent);
        String localPropName = propName.substring(propName.lastIndexOf(".") + 1);
        if (o == null) {
            PropertyDescriptor desc = getDescriptor(info, localPropName);
            String value = dict.get(propName).toString();
            o = this.convertArg(value, desc.getPropertyType());
        }
        PropertyDescriptor desc = getDescriptor(info, propName);
        desc.getWriteMethod().invoke(parent, o);
        return o;
    }

    private BeanInfo getBeanInfo(Object o) throws IntrospectionException {
        BeanInfo info = beanInfoCache.get(o.getClass());
        if (info == null) {
            info = Introspector.getBeanInfo(o.getClass());
            beanInfoCache.put(o.getClass(), info);
        }
        return info;
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
        } else {
            try {
                Class<?> paramType = Class.forName(val);
                return paramType.newInstance();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();  //CHANGEME To change body of catch statement use File | Settings | File Templates.
            } catch (InstantiationException e) {
                e.printStackTrace();  //CHANGEME To change body of catch statement use File | Settings | File Templates.
            } catch (IllegalAccessException e) {
                e.printStackTrace();  //CHANGEME To change body of catch statement use File | Settings | File Templates.
            }
        }
        return null;
    }

}
