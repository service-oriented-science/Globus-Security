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
package org.globus.security.authorization.providers;

import org.globus.security.authorization.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.*;

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

    private Map<String, PDPInterceptor> pdpMap = new HashMap<String, PDPInterceptor>();
    private Map<String, PIPInterceptor> pipMap = new HashMap<String, PIPInterceptor>();
    private Map<String, BootstrapPIP> bootstrapPipMap = new HashMap<String, BootstrapPIP>();

    private List<PDPInterceptor> pdps = new ArrayList<PDPInterceptor>();
    private List<PIPInterceptor> pips = new ArrayList<PIPInterceptor>();
    private List<BootstrapPIP> bootstrapPips = new ArrayList<BootstrapPIP>();

    private NonRequestEntities nonReqEntities;
    private String chainName;

    private Logger logger = LoggerFactory.getLogger(AbstractEngine.class.getName());

    public AbstractEngine(String chainName) {
        this.chainName = chainName;
        this.nonReqEntities = new NonRequestEntities();
    }

    /**
     * Initializes the engine with configured PDPs and PIPs. It creates an
     * instance of the configured interceptors and invokes initialize method on
     * them. Interceptors with same scope and FQDN are treated as same
     * and only one instance of such an interceptor is created.
     *
     * @param chainName A unique string which the authorization chain name
     * @throws InitializeException
     */
    public void engineInitialize(String chainName) throws InitializeException {

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
        for (String bootstrapPipId : bootstrapPipMap.keySet()) {
            bootstrapPipMap.get(bootstrapPipId).close();
        }
        for (String pipId : pipMap.keySet()) {
            pipMap.get(pipId).close();
        }
        for (String pdpId : pdpMap.keySet()) {
            pdpMap.get(pdpId).close();
        }
    }


    public void addPDP(InterceptorConfig<? extends PDPInterceptor> interceptor) throws InitializeException {
        String key = interceptor.getScope() + interceptor.getInterceptor().getClass().getCanonicalName();
        if (pdpMap.containsKey(key)) {
            this.pdps.add(pdpMap.get(key));
        } else {
            interceptor.getInterceptor().initialize(this.chainName, interceptor.getScope());
            this.pdpMap.put(key, interceptor.getInterceptor());
            this.pdps.add(interceptor.getInterceptor());
        }
    }

    public void addPIP(InterceptorConfig<? extends PIPInterceptor> pip) throws InitializeException {
        String key = pip.getScope() + pip.getInterceptor().getClass().getCanonicalName();
        if (pipMap.containsKey(key)) {
            this.pips.add(pipMap.get(key));
        } else {
            pip.getInterceptor().initialize(this.chainName, pip.getScope());
            this.pipMap.put(key, pip.getInterceptor());
            pips.add(pip.getInterceptor());
        }
    }

    public void addBootstrapPIP(InterceptorConfig<? extends BootstrapPIP> bootstrapPip) throws InitializeException {
        String key = bootstrapPip.getScope() + bootstrapPip.getInterceptor().getClass().getCanonicalName();
        if (bootstrapPipMap.containsKey(key)) {
            this.bootstrapPips.add(bootstrapPipMap.get(key));
        } else {
            bootstrapPip.getInterceptor().initialize(this.chainName, bootstrapPip.getScope());
            this.bootstrapPipMap.put(key, bootstrapPip.getInterceptor());
            this.bootstrapPips.add(bootstrapPip.getInterceptor());
        }
    }

    public List<PDPInterceptor> getPdps() {
        return Collections.unmodifiableList(pdps);
    }

    public List<PIPInterceptor> getPips() {
        return Collections.unmodifiableList(pips);
    }

    public List<BootstrapPIP> getBootstrapPips() {
        return Collections.unmodifiableList(bootstrapPips);
    }

    public NonRequestEntities getNonReqEntities() {
        return nonReqEntities;
    }

    public String getChainName() {
        return chainName;
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

        if (this.bootstrapPipMap != null) {
            for (String id : this.bootstrapPipMap.keySet()) {
                this.bootstrapPipMap.get(id).collectRequestAttributes(requestAttr);
            }
        }

        if (this.pipMap != null) {
            for (PIP pip : pips) {
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
}
