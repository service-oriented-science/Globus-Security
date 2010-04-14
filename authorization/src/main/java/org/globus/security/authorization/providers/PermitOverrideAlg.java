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

import java.util.Vector;

import org.globus.security.authorization.AuthorizationException;
import org.globus.security.authorization.Decision;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.AuthorizationContext;
import org.globus.security.authorization.NonRequestEntities;
import org.globus.security.authorization.PDP;
import org.globus.security.authorization.RequestEntities;
import org.globus.security.authorization.annotations.AuthorizationEngine;
import org.globus.security.authorization.util.AttributeUtil;
import org.globus.util.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is a combining algorithm that returns a permit if a single permit
 * decision chain can be constructed from the resource owner to the requestor.
 */
@AuthorizationEngine(name = "Permit Override Algorithm", pid = "permitOverride", description = "This is a "
		+ "combining algorithm that returns a permit if a single permit decision chain can be constructed from "
		+ "the resource owner to the requestor.", author = "Globus Crux Team")
public class PermitOverrideAlg extends AbstractEngine {

	private static final long serialVersionUID = 6701009462458338468L;

	private static I18n i18n = I18n.getI18n("org.globus.security.authorization.errors", PermitOverrideAlg.class
			.getClassLoader());

	private static Logger logger = LoggerFactory.getLogger(PermitOverrideAlg.class.getName());

	public PermitOverrideAlg(String chainName) {
		super(chainName);
	}

	public Decision engineAuthorize(RequestEntities reqAttr, EntityAttributes resourceOwnerAttributes,
			AuthorizationContext context) throws AuthorizationException {

		// set resource owner
		// this.resourceOwner = resourceOwnerAttributes;

		NonRequestEntities collectedNonReqEntities = collectAttributes(reqAttr, context).getNonRequestEntities();

		EntityAttributes requestor = reqAttr.getRequestor();
		if (requestor == null) {
			String err = i18n.getMessage("requestorNull");
			logger.error(err);
			throw new AuthorizationException(err);
		}

		if ((this.getPdps() == null) || (this.getPdps().size() == 0)) {
			String err = i18n.getMessage("noPDPs");
			logger.error(err);
			throw new AuthorizationException(err);
		}

		DecisionChainContext dcc = new DecisionChainContext(this.getPdps().size());
		dcc.setAuthorityAt(0, resourceOwnerAttributes);

		boolean checkPDP0 = true;
		DecisionChain chain = findDecisionChain(reqAttr, resourceOwnerAttributes, collectedNonReqEntities, dcc,
				context, checkPDP0, false);

		if (chain != null) {
			logger.debug("Permit decision");
			if (logger.isDebugEnabled()) {
				Decision[] decision = chain.toArray();
				for (int i = 0; i < decision.length; i++) {
					logger.debug("Decision " + i + ": " + decision[i].toString());
				}
			}
			return new Decision(resourceOwnerAttributes, requestor, Decision.PERMIT, null, null);
		} else {
			logger.debug("Deny decision ");
			Vector<Throwable> deniedExceptions = dcc.getDeniedExceptions();
			Exception exp;
			if ((deniedExceptions != null) && (deniedExceptions.size() > 0)) {
				String expStr = i18n.getMessage("denyExceptions");
				StringBuilder builder = new StringBuilder(expStr);
				for (Object deniedException : deniedExceptions) {
					builder.append("\n");
					builder.append(((Throwable) deniedException).getMessage());
					expStr = expStr + "\n" + ((Throwable) deniedException).getMessage();
				}
				exp = new Exception(expStr);
				return new Decision(resourceOwnerAttributes, requestor, Decision.DENY, null, null, exp);
			} else {
				return new Decision(resourceOwnerAttributes, requestor, Decision.DENY, null, null);
			}
		}
	}

	private Decision getDecision(RequestEntities reqAttr, NonRequestEntities nonReqAttr, AuthorizationContext context, boolean admin)
			throws AuthorizationException {
		PDP pdp0 = this.getPdps().get(0);
		Decision decision;
		if (admin) {
			decision = pdp0.canAdminister(reqAttr, this.getNonReqEntities(), context);
		} else {
			decision = pdp0.canAccess(reqAttr, this.getNonReqEntities(), context);
		}
		return decision;
	}

	private DecisionChain findDecisionChain(RequestEntities reqAttr, EntityAttributes resourceOwner,
			NonRequestEntities nonReqAttr, DecisionChainContext dcc, AuthorizationContext context, boolean checkPDP0,
			boolean admin) throws AuthorizationException {

		EntityAttributes subject = reqAttr.getRequestor();

		logger.debug("requestor " + subject);

		dcc.appendToChain(subject);
		PDP pdp0 = this.getPdps().get(0);
		Decision decision = getDecision(reqAttr, nonReqAttr, context, admin);

		// Whatever be the decision, ascertain that the issuer is the
		// resource owner
		if (checkPDP0) {
			if (decision == null) {
				String err = i18n.getMessage("authDecisionNull");
				throw new AuthorizationException(err);
			}

			if (!decision.getIssuer().isSameEntity(resourceOwner)) {
				logger.error("Issuer\n" + decision.getIssuer());
				logger.error("Resource owner\n" + resourceOwner);
				String err = i18n.getMessage("firstPDPOwner");
				throw new AuthorizationException(err);
			}
			checkPDP0 = false;
		}

		if (decision.isPermit()) {
			DecisionChain chain = new DecisionChain();
			chain.add(decision);
			dcc.removeFromChain();
			return chain;
		} else {
			dcc.addDeniedException(decision.getException());
		}
		for (int i = 1; i < getPdps().size(); i++) {
			EntityAttributes authority = dcc.getAuthorityAt(i);
			if (authority != null) {
				// if not subject owner, then cannot make decision on oneself
				if ((!subject.isSameEntity(resourceOwner)) && (subject.isSameEntity(authority))) {
					continue;
				}

				// If the authority is already in the decision chain or
				// it has been denied before, it just ignores the authority.
				if (dcc.isInChain(authority) || dcc.isDenied(authority)) {
					continue;
				}
			}
			PDP pdp = getPdps().get(i);

			// It searches for a delegation path from the resouce owner to the
			// authority.
			if (admin) {
				logger.debug("PDP " + i + " admin?");
				decision = pdp.canAdminister(reqAttr, this.getNonReqEntities(), context);
			} else {
				logger.debug("PDP " + i + " access?");
				decision = pdp.canAccess(reqAttr, this.getNonReqEntities(), context);
			}

			// Check if some attributes have been collected about
			// issuer
			EntityAttributes decisionIssuer = decision.getIssuer();
			EntityAttributes completeAttrIssuer = AttributeUtil.getMatchedEntity(nonReqAttr.getSubjectAttrsList(),
					decisionIssuer);
			if (completeAttrIssuer != null) {
				decisionIssuer.mergeEntities(completeAttrIssuer);
			}

			logger.debug("After merge of attributes, decsion issuser:  " + decisionIssuer);

			// set authority for particular PDP
			dcc.setAuthorityAt(i, decisionIssuer);

			if (decision.isPermit()) {
				// if issuer is resource owner, then chain can stop
				// here
				if (decisionIssuer.isSameEntity(resourceOwner)) {
					logger.debug("issuer decision");
					DecisionChain chain = new DecisionChain();
					chain.add(decision);
					dcc.removeFromChain();
					return chain;
				} else {
					RequestEntities newReqAttr = new RequestEntities(dcc.getAuthorityAt(i), reqAttr.getAction(),
							reqAttr.getResource(), reqAttr.getEnvironment());
					DecisionChain chain = findDecisionChain(newReqAttr, resourceOwner, nonReqAttr, dcc, context,
							checkPDP0, true);
					if (chain != null) {
						// It got a chain. So return it to the
						// caller
						chain.add(decision);
						dcc.removeFromChain();
						return chain;
					}
				}
			} else {
				dcc.addDeniedException(decision.getException());
			}
		}
		// No chain is found! It means that there is no way for the authority
		// to get a permission. So, it just puts the authority to the
		// deny list and returns to the caller with no result.
		dcc.addToDeniedList(subject);
		dcc.removeFromChain();
		return null;
	}

	public String getAlgorithm() {
		return "PermitOverride";
	}
}
