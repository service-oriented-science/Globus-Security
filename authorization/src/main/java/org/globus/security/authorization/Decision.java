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

    private static I18nUtil i18n =
            I18nUtil.getI18n("org.globus.security.authorization.errors",
                    Decision.class.getClassLoader());

    public static final int PERMIT = 2;
    public static final int INDETERMINATE = 1;
    public static final int NOT_APPLICABLE = 0;
    public static final int DENY = -1;

    private EntityAttributes issuer = null;
    private EntityAttributes subject = null;
    private int decision = -2;
    private Throwable exception = null;
    private Calendar notBefore = null;
    private Calendar notAfter = null;

    public Decision(EntityAttributes issuer, EntityAttributes subject,
                    int decision, Calendar notBefore, Calendar notAfter) {
        this(issuer, subject, decision, notBefore, notAfter, null);
    }

    /**
     * Constructor
     *
     * @param issuer_    Issuer of decision. Cannot be null.
     * @param subject_   Subject the decision is on. Cannot be null.
     * @param decision_  indicates decision
     * @param notBefore_ Timestamp after which decision is valid
     * @param notAfter_  Timestamp upto which the decision is valid
     * @param exception_ Any exception returned as part of decision.
     */
    public Decision(EntityAttributes issuer_, EntityAttributes subject_,
                    int decision_, Calendar notBefore_, Calendar notAfter_,
                    Throwable exception_) {

        if (issuer_ == null) {
            String err = i18n.getMessage("issuerNotNull");
            throw new IllegalArgumentException(err);
        }

        if (subject_ == null) {
            String err = i18n.getMessage("subjectNotNull");
            throw new IllegalArgumentException(err);
        }

        this.issuer = issuer_;
        this.subject = subject_;
        this.decision = decision_;
        this.exception = exception_;
        this.notBefore = notBefore_;
        this.notAfter = notAfter_;
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
        String ret = "Decision(issuer=" + issuer + ", subject=" + subject +
                ", decision=" + decision + " exception " + this.exception;
        return ret;
    }

    public boolean isPermit() {
        return (PERMIT == this.decision);
    }

    public boolean isDeny() {
        return (DENY == this.decision);
    }
}
