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
package org.globus.security.authorization;

import java.util.Calendar;

import org.globus.security.authorization.util.I18nUtil;

/**
 * Data type returned by a PDP.
 */
public class Decision {

    public static final int PERMIT = 2;
    public static final int INDETERMINATE = 1;
    public static final int NOT_APPLICABLE = 0;
    public static final int DENY = -1;

    private static I18nUtil i18n =
        I18nUtil.getI18n("org.globus.security.authorization.errors",
            Decision.class.getClassLoader());

    private EntityAttributes issuer;
    private EntityAttributes subject;
    private int decision = -2;
    private Throwable exception;
    private Calendar notBefore;
    private Calendar notAfter;

    public Decision(
        EntityAttributes issuer, EntityAttributes subject,
        int decision, Calendar notBefore, Calendar notAfter) {
        this(issuer, subject, decision, notBefore, notAfter, null);
    }

    /**
     * Constructor
     *
     * @param initIssuer    Issuer of decision. Cannot be null.
     * @param initSubject   Subject the decision is on. Cannot be null.
     * @param initDecision  indicates decision
     * @param initNotBefore Timestamp after which decision is valid
     * @param initNotAfter  Timestamp upto which the decision is valid
     * @param initException Any exception returned as part of decision.
     */
    public Decision(
        EntityAttributes initIssuer, EntityAttributes initSubject,
        int initDecision, Calendar initNotBefore, Calendar initNotAfter,
        Throwable initException) {

        if (initIssuer == null) {
            String err = i18n.getMessage("issuerNotNull");
            throw new IllegalArgumentException(err);
        }

        if (initSubject == null) {
            String err = i18n.getMessage("subjectNotNull");
            throw new IllegalArgumentException(err);
        }

        this.issuer = initIssuer;
        this.subject = initSubject;
        this.decision = initDecision;
        this.exception = initException;
        this.notBefore = initNotBefore;
        this.notAfter = initNotAfter;
    }

    public EntityAttributes getIssuer() {
        return issuer;
    }

    public EntityAttributes getSubject() {
        return subject;
    }

    public int getDecision() {
        return decision;
    }

    public Throwable getException() {
        return this.exception;
    }

    public Calendar getNotBefore() {
        return this.notBefore;
    }

    public Calendar getNotAfter() {
        return this.notAfter;
    }

    public String toString() {
        return "Decision(issuer=" + issuer + ", subject=" + subject + ", decision="
            + decision + " exception " + this.exception;
    }

    public boolean isPermit() {
        return PERMIT == this.decision;
    }

    public boolean isDeny() {
        return DENY == this.decision;
    }
}
