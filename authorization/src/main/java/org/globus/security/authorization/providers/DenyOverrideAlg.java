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

import org.globus.security.authorization.AuthorizationException;
import org.globus.security.authorization.Decision;
import org.globus.security.authorization.EntityAttributes;
import org.globus.security.authorization.PDPInterceptor;
import org.globus.security.authorization.RequestEntities;
import org.globus.security.authorization.util.I18nUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This combining algorithm returns the first deny decision returned
 * by the list of configuired PDPs.
 * <p/>
 * Steps:
 * Invoke all configured PIPs in order.
 * Invoke each PDP in order.
 * If a PDP returns a deny, return decision.
 * If all PDPs return a permit, return permit.
 * If no PDPs provide a decision, return indeterminate.
 * <p/>
 * Note that entity issuing the decision for each PDP is not
 * considered, that is the resource owner is not matched with PDP
 * decision issuer. Resource owner is used only when an indeterminate
 * decision is returned, with no decision from any PDPs.
 */
public class DenyOverrideAlg extends AbstractEngine {

    private static I18nUtil i18n = I18nUtil.getI18n("org.globus.security.authorization.errors",
        DenyOverrideAlg.class.getClassLoader());

    private static Logger logger = LoggerFactory.getLogger(DenyOverrideAlg.class.getName());

    public Decision engineAuthorize(RequestEntities reqAttr, EntityAttributes resourceOwner)
        throws AuthorizationException {

        collectAttributes(reqAttr);

        if ((this.pdps == null) || (this.pdps.length < 1)) {
            String err = i18n.getMessage("noPDPs");
            logger.error(err);
            throw new AuthorizationException(err);
        }

        boolean permit = true;
        for (PDPInterceptor pdp : this.pdps) {

            Decision decision = pdp.canAccess(reqAttr, this.nonReqEntities);

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
}
