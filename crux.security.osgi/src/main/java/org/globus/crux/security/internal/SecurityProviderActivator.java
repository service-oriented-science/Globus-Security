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

import java.io.File;
import java.io.IOException;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Properties;

import org.mortbay.component.LifeCycle;
import org.mortbay.jetty.Handler;
import org.mortbay.jetty.HandlerContainer;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.handler.HandlerWrapper;
import org.mortbay.util.Attributes;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.service.cm.ManagedService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class SecurityProviderActivator implements BundleActivator {
    /**
     * logger
     */
    private static final Logger log = LoggerFactory.getLogger(SecurityProviderActivator.class.getName());

    private Server server;

    private BundleContext bundleContext;

    private ServiceRegistration serviceRegistration;

    private JettyConfigService jcService;

    private ServiceRegistration configRegistration;

    public void start(BundleContext context) throws Exception {
        this.bundleContext = context;
        log.info("start SecurityProviderActivator");

        // do the initialization on a different thread
        // so the activator finishes fast
        Thread startupThread = new Thread(new Runnable() {

            public void run() {
                log.info("Starting Jetty " + Server.getVersion() + " ...", null, null);

                // create logging directory first
                createLoggingDirectory();

                // default startup
                //  procedure
                ClassLoader cl = SecurityProviderActivator.class.getClassLoader();
                Thread current = Thread.currentThread();
                ClassLoader old = current.getContextClassLoader();

                try {
                    //current.setContextClassLoader(cl);
                    //reset CCL
                    current.setContextClassLoader(null);
                    server = new Server();
                    ServiceReference configurationAdminReference =
                            bundleContext.getServiceReference(ConfigurationAdmin.class.getName());


                    jcService = new JettyConfigService(server);
                    log.info("Succesfully started Jetty " + Server.getVersion(), null, null);

                    // publish server as an OSGi service
                    serviceRegistration = publishServerAsAService(server);
                    jcService = new JettyConfigService(server);
                    Dictionary<String, String> props = new Hashtable<String, String>();
                    props.put(Constants.SERVICE_PID, JettyConfigService.class.getCanonicalName());
                    configRegistration = bundleContext.registerService(ManagedService.class.getName(),
                            jcService, props);

                    log.info("Published Jetty " + Server.getVersion() + " as an OSGi service", null, null);
                    server.start();
                    server.join();
                }
                catch (Exception ex) {
                    String msg = "Cannot start Jetty " + Server.getVersion();
                    log.warn(msg, ex);
                    throw new RuntimeException(msg, ex);
                }
                finally {
                    current.setContextClassLoader(old);
                }
            }
        }, "Jetty Start Thread");

        startupThread.start();
    }

    public void stop(BundleContext context) throws Exception {
        // unpublish service first
        serviceRegistration.unregister();
        configRegistration.unregister();

        log.info("Unpublished Jetty " + Server.getVersion() + " OSGi service", null, null);

        // default startup procedure
        ClassLoader cl = SecurityProviderActivator.class.getClassLoader();
        Thread current = Thread.currentThread();
        ClassLoader old = current.getContextClassLoader();

        try {
            log.info("Stopping Jetty " + Server.getVersion() + " ...", null, null);
            //current.setContextClassLoader(cl);
            //reset CCL
            current.setContextClassLoader(null);
            server.stop();
            log.info("Succesfully stopped Jetty " + Server.getVersion() + " ...", null, null);
        }
        catch (Exception ex) {
            log.warn("Cannot stop Jetty " + Server.getVersion(), ex);
            throw ex;
        }
        finally {
            current.setContextClassLoader(old);
        }
    }

    private ServiceRegistration publishServerAsAService(Server server) {
        Properties props = new Properties();
        // put some extra properties to easily identify the service
        props.put(Constants.SERVICE_VENDOR, "Globus Crux");
        props.put(Constants.SERVICE_DESCRIPTION, "Jetty " + Server.getVersion() + " with SSL Proxy Support");
        props.put(Constants.BUNDLE_VERSION, Server.getVersion());
        props.put(Constants.BUNDLE_NAME, bundleContext.getBundle().getSymbolicName());

        // spring-dm specific property
//        props.put("org.springframework.osgi.bean.name", "jetty-server");

        // publish just the interfaces and the major classes (server/handlerWrapper)
        String[] classes = new String[]{Server.class.getName(), HandlerWrapper.class.getName(),
                Attributes.class.getName(), HandlerContainer.class.getName(), Handler.class.getName(),
                LifeCycle.class.getName()};
        return bundleContext.registerService(classes, server, props);
    }

    private void createLoggingDirectory() {
        try {
            File logs = new File(".", "logs");
            if (!logs.exists())
                logs.mkdir();
            String path = logs.getCanonicalPath();
            System.setProperty("jetty.logs", path);
            log.info("Created Jetty logging folder " + path, null, null);
        }
        catch (IOException ex) {
            log.warn("Cannot create logging folder", ex);
        }

    }

}
