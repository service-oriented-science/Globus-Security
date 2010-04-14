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
import org.globus.security.authorization.GlobusContext;
import org.globus.security.authorization.NonRequestEntities;
import org.globus.security.authorization.PDPInterceptor;
import org.globus.security.authorization.RequestEntities;
import org.globus.security.authorization.annotations.AuthorizationEngine;
import org.globus.util.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This combining algorithm returns the first permit or return decision returned
 * by the list of configured PDPs. Steps: Invoke all configured PIPs in order.
 * <ol>
 * <li>Invoke each PDP in order.</li>
 * <li>If a PDP returns a permit or deny, return decision.</li>
 * <li>If no PDPs provide a decision, return indeterminate.</li>
 * </ol>
 * <p/>
 * Note that entity issuing the decision for each PDP is not considered, that is
 * the resource owner is not matched with PDP decision issuer. Resource owner is
 * used only when an indeterminate decision is returned, with no decision from
 * any PDPs.
 */
@AuthorizationEngine(name = "First Apllicable Algorithm", description = "This combining algorithm returns the first permit or return decision returned "
		+ "by the list of configured PDPs", documentationPath = "/firstApplicable.html", author = "Globus Crux Team", pid = "FirstApplicable")
public class FirstApplicableAlg extends AbstractEngine {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6958049485606617224L;

	private static I18n i18n = I18n.getI18n("org.globus.security.authorization.errors", FirstApplicableAlg.class
			.getClassLoader());

	private static Logger logger = LoggerFactory.getLogger(FirstApplicableAlg.class.getName());

	public FirstApplicableAlg(String chainName) {
		super(chainName);
	}

	public Decision engineAuthorize(RequestEntities reqAttr, EntityAttributes resourceOwner, GlobusContext context)
			throws AuthorizationException {

		NonRequestEntities collectedNonReqEntities = collectAttributes(reqAttr, context).getNonRequestEntities();

		if ((getPdps() == null) || (this.getPdps().size() == 0)) {
			String err = i18n.getMessage("noPDPs");
			logger.error(err);
			throw new AuthorizationException(err);
		}

		for (PDPInterceptor pdp : this.getPdps()) {
			Decision decision = pdp.canAccess(reqAttr, collectedNonReqEntities, context);

			if (decision == null) {
				continue;
			}

			if (decision.isPermit() || decision.isDeny()) {
				return decision;
			}
		}

		return new Decision(reqAttr.getRequestor(), resourceOwner, Decision.INDETERMINATE, null, null);
	}

	public String getAlgorithm() {
		return "FirstApplicable";
	}

}
