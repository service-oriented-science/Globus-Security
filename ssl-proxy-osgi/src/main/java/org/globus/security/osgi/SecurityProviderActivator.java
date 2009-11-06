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
package org.globus.security.osgi;

import java.security.Security;

import org.globus.security.provider.GlobusProvider;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class SecurityProviderActivator implements BundleActivator{
    private Logger logger = LoggerFactory.getLogger(getClass());

    public void start(BundleContext bundleContext) throws Exception {
        logger.info("Loading Globus Security Provider");
        Security.addProvider(new GlobusProvider());

    }

    public void stop(BundleContext bundleContext) throws Exception {
        logger.info("Loading Globus Security Provider");
        Security.removeProvider(GlobusProvider.PROVIDER_NAME);
    }
}
