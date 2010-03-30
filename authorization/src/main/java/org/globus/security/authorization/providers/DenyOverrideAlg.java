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

import org.globus.security.authorization.AuthorizationException;
import org.globus.security.authorization.Decision;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.PDPInterceptor;
import org.globus.security.authorization.RequestEntities;
import org.globus.security.authorization.annotations.AuthorizationEngine;
import org.globus.util.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This combining algorithm returns the first deny decision returned by the list
 * of configuired PDPs.
 * <p/>
 * Steps: Invoke all configured PIPs in order.
 * 
 * <ol>
 * <li>Invoke each PDP in order.</li>
 * <li>If a PDP returns a deny, return decision.</li>
 * <li>If all PDPs return a permit, return permit.</li>
 * <li>If no PDPs provide a decision, return indeterminate.</li>
 * </ol>
 * <p/>
 * Note that entity issuing the decision for each PDP is not considered, that is
 * the resource owner is not matched with PDP decision issuer. Resource owner is
 * used only when an indeterminate decision is returned, with no decision from
 * any PDPs.
 */
@AuthorizationEngine(name = "Deny Override Algorithm", description = "This combining algorithm returns the first "
		+ "deny decision returned by the list of configuired PDPs", documentationPath = "/denyOverride.html", author = "Globus Crux Team", pid = "DenyOverride")
public class DenyOverrideAlg extends AbstractEngine {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1634123231473744560L;

	private static I18n i18n = I18n.getI18n("org.globus.security.authorization.errors", DenyOverrideAlg.class
			.getClassLoader());

	private Logger logger = LoggerFactory.getLogger(DenyOverrideAlg.class.getName());

	public DenyOverrideAlg(String chainName) {
		super(chainName);
	}

	public Decision engineAuthorize(RequestEntities reqAttr, EntityAttributes resourceOwner)
			throws AuthorizationException {

		collectAttributes(reqAttr);

		if ((this.getPdps() == null) || (this.getPdps().size() == 0)) {
			String err = i18n.getMessage("noPDPs");
			logger.error(err);
			throw new AuthorizationException(err);
		}

		boolean permit = true;
		for (PDPInterceptor pdp : this.getPdps()) {

			Decision decision = pdp.canAccess(reqAttr, this.getNonReqEntities());

			if (decision == null) {
				permit = false;
			} else {
				if (decision.isDeny()) {
					return decision;
				} else if (!decision.isPermit()) {
					permit = false;
				}
			}
		}

		if (permit) {
			return new Decision(reqAttr.getRequestor(), resourceOwner, Decision.PERMIT, null, null);
		} else {
			return new Decision(reqAttr.getRequestor(), resourceOwner, Decision.INDETERMINATE, null, null);
		}
	}

	public String getAlgorithm() {
		return "DenyOverride";
	}
}
