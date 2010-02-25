/*
 *
 * Copyright 1999-2010 University of Chicago
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

import java.io.Serializable;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.globus.security.authorization.AttributeException;
import org.globus.security.authorization.AuthorizationEngineSpi;
import org.globus.security.authorization.AuthorizationException;
import org.globus.security.authorization.BootstrapPIP;
import org.globus.security.authorization.CloseException;
import org.globus.security.authorization.Decision;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.NonRequestEntities;
import org.globus.security.authorization.PDPInterceptor;
import org.globus.security.authorization.PIPInterceptor;
import org.globus.security.authorization.RequestEntities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract engine class that can be extended from to implement authorization
 * engines with specific combining algorithms. Assumes that the configuration
 * classes are also used. The implementation needs to override the abstract
 * method with the logic to combine PDP decisions.
 * <p/>
 * The abstract engine initialized the interceptors in the order it is
 * specified. Interceptors with same scope and FQDN are treated as the same
 * interceptor and only once instance of such an interceptor is created. So the
 * same object is used for processing, for every occurannce of the interceptor
 * in the chain.
 * <p/>
 * The class also provides a simple algorithm to collect all attributes by
 * invoking configured bootstrap PIPs in order and then the configured PIPs in
 * configured order. The collected attributes are examined to merge attributes
 * about the same entity. This method is NOT invoked by the abstract engine, but
 * needs to invoked by the actual implementation as appropriate.
 */
@SuppressWarnings("serial")
public abstract class AbstractEngine implements AuthorizationEngineSpi, Serializable {

//	private static I18n i18n = I18n.getI18n("engine_messages");
	protected List<PDPInterceptor> pdps;
	protected List<PIPInterceptor> pips;
	protected List<BootstrapPIP> bootstrapPips;

	private NonRequestEntities nonReqEntities;
	private String chainName;
	
	private Logger logger = LoggerFactory.getLogger(AbstractEngine.class.getName());

	public AbstractEngine(String chainName) {
		this.chainName = chainName;
		this.nonReqEntities = new NonRequestEntities();
	}
		
	public String getChainName() {
		return chainName;
	}

	public void setChainName(String chainName) {
		this.chainName = chainName;
	}

	/**
	 * This method contains the logic for processing the PIPs and PDPs.
	 * 
	 * @param reqAttribute
	 *            Attributes about the request entities.
	 * @param resourceOwner
	 *            Resource owner entity
	 * @return Decision object
	 * @throws AuthorizationException
	 */
	abstract public Decision engineAuthorize(RequestEntities reqAttribute, EntityAttributes resourceOwner)
			throws AuthorizationException;

	/**
	 * Invokes close on all interceptor.
	 * 
	 * @throws CloseException
	 */
	public void engineClose() throws CloseException {
		for(BootstrapPIP bp: bootstrapPips){
			bp.close();
		}
		for(PIPInterceptor pip: pips){
			pip.close();
		}
		for(PDPInterceptor pdp: pdps){
			pdp.close();
		}
	}	
	
	
	
	protected NonRequestEntities getNonReqEntities() {
		return nonReqEntities;
	}

	public void setPDPInterceptors(final List<? extends PDPInterceptor> pdpInterceptors){
		pdps = Collections.unmodifiableList(pdpInterceptors);
	}		
	
	protected List<? extends PDPInterceptor> getPdps() {
		return pdps;
	}

	protected List<? extends PIPInterceptor> getPips() {
		return pips;
	}

	protected List<? extends BootstrapPIP> getBootstrapPips() {
		return bootstrapPips;
	}

	public void setPIPInterceptors(final List<? extends PIPInterceptor> pipInterceptors){
		pips = Collections.unmodifiableList(pipInterceptors);
	}
	
	public void setBootstrapPIPS(final List<? extends BootstrapPIP> bootstrapPIPs){
		bootstrapPips = Collections.unmodifiableList(bootstrapPIPs);
	}

	/**
	 * Invoked collectAttributes on all configured Bootstrap PIPs and PIPs, in
	 * the order they were invoked. The returned attributes are processed to
	 * merge any attributes for the same entity
	 * 
	 * @param requestAttr
	 * @throws AttributeException
	 */
	protected void collectAttributes(RequestEntities requestAttr) throws AttributeException {

		if (this.bootstrapPips != null) {
			for(BootstrapPIP bp: bootstrapPips){
				bp.collectRequestAttributes(requestAttr);
			}
		}

		if (this.pips != null) {
			for(PIPInterceptor pip: pips){
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
					Iterator<EntityAttributes> it = this.nonReqEntities.getSubjectAttrsList().iterator();
					while (it.hasNext()) {
						logger.debug(it.next().toString());
					}
				} else {
					logger.debug("Non request attributes are null");
				}
			}
		}
	}	
}
