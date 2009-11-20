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
package org.globus.security.jetty;

import javax.servlet.Servlet;

import org.ops4j.pax.web.service.spi.Configuration;
import org.ops4j.pax.web.service.spi.ServerController;
import org.ops4j.pax.web.service.spi.ServerListener;
import org.ops4j.pax.web.service.spi.model.ContextModel;
import org.ops4j.pax.web.service.spi.model.ErrorPageModel;
import org.ops4j.pax.web.service.spi.model.EventListenerModel;
import org.ops4j.pax.web.service.spi.model.FilterModel;
import org.ops4j.pax.web.service.spi.model.ServletModel;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class Jetty7ServerController implements ServerController {
    public void start() {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void stop() {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public boolean isStarted() {
        return false;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public boolean isConfigured() {
        return false;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void configure(Configuration configuration) {

        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public Configuration getConfiguration() {
        return null;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void addListener(ServerListener serverListener) {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void removeContext(org.osgi.service.http.HttpContext httpContext) {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void addServlet(ServletModel servletModel) {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void removeServlet(ServletModel servletModel) {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void addEventListener(EventListenerModel eventListenerModel) {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void removeEventListener(EventListenerModel eventListenerModel) {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void addFilter(FilterModel filterModel) {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void removeFilter(FilterModel filterModel) {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void addErrorPage(ErrorPageModel errorPageModel) {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public void removeErrorPage(ErrorPageModel errorPageModel) {
        //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public Integer getHttpPort() {
        return null;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public Integer getHttpSecurePort() {
        return null;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }

    public Servlet createResourceServlet(ContextModel contextModel, String s, String s1) {
        return null;  //CHANGEME To change body of implemented methods use File | Settings | File Templates.
    }
}
