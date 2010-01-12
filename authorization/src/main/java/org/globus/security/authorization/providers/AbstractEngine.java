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
package org.globus.security.authorization.providers;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.globus.security.authorization.AttributeException;
import org.globus.security.authorization.AuthorizationConfig;
import org.globus.security.authorization.AuthorizationEngineSpi;
import org.globus.security.authorization.AuthorizationException;
import org.globus.security.authorization.BootstrapPIP;
import org.globus.security.authorization.ChainConfig;
import org.globus.security.authorization.CloseException;
import org.globus.security.authorization.Decision;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.InitializeException;
import org.globus.security.authorization.Interceptor;
import org.globus.security.authorization.InterceptorConfig;
import org.globus.security.authorization.NonRequestEntities;
import org.globus.security.authorization.PDPInterceptor;
import org.globus.security.authorization.PIPInterceptor;
import org.globus.security.authorization.RequestEntities;
import org.globus.security.authorization.util.I18nUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract engine class that can be extended from to implement authorization
 * engines with specific combining algorithms. Assumes that the configuration
 * classes are also used. The implementation needs to override the abstract
 * method with the logic to combine PDP decisions.
 * <p/>
 * The abstract engine initialized the interceptors in the order it is
 * specified. Interceptors with same scope and FQDN are treated as the
 * same interceptor and only once instance of such an interceptor is
 * created. So the same object is used for processing, for every
 * occurannce of the interceptor in the chain.
 * <p/>
 * The class also provides a simple algorithm to collect all attributes by
 * invoking configured bootstrap PIPs in order and then the configured PIPs
 * in configured order. The collected attributes are examined to merge
 * attributes about the same entity. This method is NOT invoked by the abstract
 * engine, but needs to invoked by the actual implementation as appropriate.
 */
public abstract class AbstractEngine implements AuthorizationEngineSpi, Serializable {

    protected static final int BOOTSTRAP_PIP = 0;
    protected static final int PIP_INTERCEPTOR = 1;
    protected static final int PDP_INTERCEPTOR = 2;

    private static I18nUtil i18n = I18nUtil.getI18n("org.globus.security.authorization.errors",
        AbstractEngine.class.getClassLoader());

    protected PDPInterceptor[] pdps;
    protected PIPInterceptor[] pips;
    protected BootstrapPIP[] bootstrapPips;

    protected NonRequestEntities nonReqEntities;

    protected ChainConfig chainConfig;

    private Logger logger = LoggerFactory.getLogger(AbstractEngine.class.getName());

    /**
     * Initializes the engine with configured PDPs and PIPs. It creates an
     * instance of the configured interceptors and invokes initialize method on
     * them. Interceptors with same scope and FQDN are treated as same
     * and only one instance of such an interceptor is created.
     *
     * @param chainName       A unique string which the authorization chain name
     * @param authzConfig     An object of <code>AuthorizationConfig</code> containing the list
     *                        of Bootstrap PIPs, PIPs and PDPs.
     * @param initChainConfig Configuration object with all configuration for th
     * @throws InitializeException
     */
    public void engineInitialize(String chainName, AuthorizationConfig authzConfig, ChainConfig initChainConfig)
        throws InitializeException {

        this.chainConfig = initChainConfig;

        this.nonReqEntities = new NonRequestEntities();

        initializeInterceptors(chainName, authzConfig);
    }

    /**
     * Thie method contains the logic for processing the PIPs and PDPs.
     *
     * @param reqAttribute  Attributes about the request entities.
     * @param resourceOwner Resource owner entity
     * @return Decision object
     * @throws AuthorizationException
     */
    public abstract Decision engineAuthorize(RequestEntities reqAttribute, EntityAttributes resourceOwner)
        throws AuthorizationException;

    /**
     * Invokes close on all interceptors.
     *
     * @throws CloseException
     */
    public void engineClose() throws CloseException {
        for (BootstrapPIP bootstrapPip : bootstrapPips) {
            bootstrapPip.close();
        }
        for (PIPInterceptor pip : pips) {
            pip.close();
        }
        for (PDPInterceptor pdp : pdps) {
            pdp.close();
        }
    }

    public ChainConfig getChainConfig() {
        return this.chainConfig;
    }

    protected synchronized void initializeInterceptors(String chainName, AuthorizationConfig authzConfig)
        throws InitializeException {

        if (authzConfig == null) {
            String err = i18n.getMessage("noInterceptors");
            logger.error(err);
            throw new InitializeException(err);
        }

        // bootstrap
        InterceptorConfig[] interConfig = authzConfig.getBootstrapPips();
        if (interConfig != null) {

            this.bootstrapPips = new BootstrapPIP[interConfig.length];
            initializeInterceptors(interConfig, this.bootstrapPips, chainName,
                BOOTSTRAP_PIP);
        }

        // PIPs
        interConfig = authzConfig.getPips();
        if (interConfig != null) {
            this.pips = new PIPInterceptor[interConfig.length];
            initializeInterceptors(interConfig, this.pips, chainName,
                PIP_INTERCEPTOR);
        }

        // PDPs
        interConfig = authzConfig.getPdps();
        if (interConfig != null) {
            this.pdps = new PDPInterceptor[interConfig.length];
            initializeInterceptors(interConfig, this.pdps, chainName,
                PDP_INTERCEPTOR);
        }
    }

    protected void initializeInterceptors(
        InterceptorConfig[] config, Interceptor[] interceptors, String chainName,
        int type)
        throws InitializeException {

        if ((config == null) || (interceptors == null)) {
            throw new IllegalArgumentException();
        }

        Map<String, Interceptor> interceptorMap = new HashMap<String, Interceptor>();

        for (int i = 0; i < config.length; i++) {
            String key = config[i].getScope() + config[i].getInterceptorFQDN();
            try {
                if (type == BOOTSTRAP_PIP) {
                    if (interceptorMap.containsKey(key)) {
                        interceptors[i] = interceptorMap.get(key);
                    } else {
                        interceptors[i] = (BootstrapPIP) loadClass(config[i].getInterceptorFQDN()).newInstance();
                        interceptors[i].initialize(chainName, config[i].getScope(), this.chainConfig);
                        interceptorMap.put(key, interceptors[i]);
                    }
                } else if (type == PIP_INTERCEPTOR) {
                    if (interceptorMap.containsKey(key)) {
                        interceptors[i] = interceptorMap.get(key);
                    } else {
                        interceptors[i] = (PIPInterceptor) loadClass(config[i].getInterceptorFQDN()).newInstance();
                        interceptors[i].initialize(chainName, config[i].getScope(), this.chainConfig);
                        interceptorMap.put(key, interceptors[i]);
                    }
                } else if (type == PDP_INTERCEPTOR) {
                    if (interceptorMap.containsKey(key)) {
                        interceptors[i] = interceptorMap.get(key);
                    } else {
                        interceptors[i] = (PDPInterceptor) loadClass(config[i].getInterceptorFQDN()).newInstance();
                        interceptors[i].initialize(chainName, config[i].getScope(), this.chainConfig);
                        interceptorMap.put(key, interceptors[i]);
                    }
                }
            } catch (Exception e) {
                String err = i18n.getMessage("loadInterceptors", config[i]);
                logger.error(err, e);
                throw new InitializeException(err, e);
            }
        }
    }

    /**
     * Invoked collectAttributes on all configured Bootstrap PIPs and PIPs, in
     * the order they were invoked. The returned attributes are processed to
     * merge any attributes for the same entity
     *
     * @param requestAttr Fill Me
     * @throws AttributeException Fill Me
     */
    protected void collectAttributes(RequestEntities requestAttr) throws AttributeException {

        if (this.bootstrapPips != null) {
            for (BootstrapPIP bootstrapPip : this.bootstrapPips) {
                bootstrapPip.collectRequestAttributes(requestAttr);
            }
        }

        if (this.pips != null) {
            for (PIPInterceptor pip : pips) {
                NonRequestEntities response = pip.collectAttributes(requestAttr);
                if (this.nonReqEntities == null) {
                    this.nonReqEntities = response;
                } else {
                    this.nonReqEntities.merge(response);
                }
            }

            if (logger.isDebugEnabled()) {
                if (this.nonReqEntities != null) {
                    logger.debug("Subject attribute list after merge ");
                    for (Object o : this.nonReqEntities.getSubjectAttrsList()) {
                        logger.debug(o.toString());
                    }
                } else {
                    logger.debug("Non request attributes are null");
                }
            }
        }
    }

    // from CoG

    protected Class loadClass(String fqdn) throws ClassNotFoundException {

        ClassLoader loader = this.getClass().getClassLoader();
        try {
            return Class.forName(fqdn, true, loader);
        } catch (ClassNotFoundException e) {
            // try with context classloader if set & different
            ClassLoader contextLoader = Thread.currentThread().getContextClassLoader();
            if (contextLoader == null || contextLoader == loader) {
                throw e;
            } else {
                return Class.forName(fqdn, true, contextLoader);
            }
        }

    }
}
