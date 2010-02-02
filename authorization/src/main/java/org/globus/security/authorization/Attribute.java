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
package org.globus.security.authorization;

import org.globus.security.authorization.util.I18nUtil;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Data type representing an attribute.
 * Attribute is uniquely identified by AttributeIdentifier. It has an
 * issuer, validity time stamps and set of values of same datatype
 * (not ensured in code), without any duplicates.
 */
public class Attribute<T> implements Serializable {

    private static I18nUtil i18n =
            I18nUtil.getI18n("org.globus.security.authorization.errors",
                    Attribute.class.getClassLoader());

    private Calendar validFrom;
    private Calendar validTill;
    private AttributeIdentifier attributeId;
    private Set<T> valueSet;
    private EntityAttributes issuer;

    @SuppressWarnings("unused")
    private Attribute() {
        //Should not use 
    }

    public Attribute(AttributeIdentifier initAttributeId, EntityAttributes initIssuer, Calendar validFrom,
                     Calendar validTill) {
        this(initAttributeId, initIssuer, validFrom, validTill, null);
    }

    /**
     * Constructor
     *
     * @param initAttributeId AttributeIdentifier object. Cannot be null
     * @param initIssuer      Issuer of asertion. If this is null, the framework
     *                        assumes that the container is the issuer. All PIPs must
     *                        make sure that this value it filled, if contiane should not be
     *                        assumed to be the owner.
     * @param initValidFrom   Time stamp from which attribute is valid. Cannot be null.
     * @param initValidTo     Time until which attribute is valid. Must beafter initValidFrom
     * @param values          Contents of this set are added as attribute values.
     */
    public Attribute(AttributeIdentifier initAttributeId, EntityAttributes initIssuer, Calendar initValidFrom,
                     Calendar initValidTo, Set<T> values) {

        if (initAttributeId == null) {
            String err = i18n.getMessage("attrIdNotNull");
            throw new IllegalArgumentException(err);
        }

        if (initValidFrom == null) {
            String err = i18n.getMessage("validFromNotNull");
            throw new IllegalArgumentException(err);
        }

        if ((initValidTo != null) && (initValidTo.before(initValidFrom))) {
            String err = i18n.getMessage("badValidTill");
            throw new IllegalArgumentException(err);
        }

        this.attributeId = initAttributeId;
        this.issuer = initIssuer;
        this.validFrom = initValidFrom;
        this.validTill = initValidTo;

        if (values != null) {
            this.valueSet = Collections.synchronizedSet(new HashSet<T>(values));
        }
    }

    /**
     * Returns issuer of assertion.
     *
     * @return Fill Me
     */
    public EntityAttributes getIssuer() {
        return this.issuer;
    }


    /**
     * Overwrites the existing collection of values, with this set.
     *
     * @param values Fill Me
     */
    public void setAttributeValueSet(Set<T> values) {
        this.valueSet = Collections.synchronizedSet(new HashSet<T>(values));
    }

    /**
     * Adds this object to the attribute value set.
     *
     * @param object Fill Me
     */
    public void addAttributeValue(T object) {
        if (object != null) {
            if (this.valueSet == null) {
                this.valueSet = Collections.synchronizedSet(new HashSet<T>());
            }
            this.valueSet.add(object);
        }
    }

    /**
     * Returns attribute value as a set.
     *
     * @return Fill Me
     */
    public Set<T> getAttributeValueSet() {
        return this.valueSet;
    }

    /**
     * Returns AttributeIdentifier
     *
     * @return Fill Me
     */
    public AttributeIdentifier getAttributeIdentifier() {
        return this.attributeId;
    }

    /*
     * Returns true of the attribute is an identity attribute.
     *
     */

    public boolean isIdentityAttribute() {
        return this.attributeId.isIdentityAttribute();
    }

    /**
     * Returns timestamp from when this attribute is valid
     *
     * @return Fill Me
     */
    public Calendar getValidFrom() {
        return this.validFrom;
    }

    /**
     * @return Fill Me
     */
    public Calendar getValidTill() {
        return this.validTill;
    }

    /**
     * This method is used to compare if the attribute is semantically
     * equivalent to the one passed as parameter and is a subjective comparison
     * of the attributes.
     * <p/>
     * The attributes are deemed the same if attributeId matches, issuer entity
     * matches (refer <code>EntityAttributes.isSameEntity</code>) and atleast
     * one value matches. Time stamps are ignored.
     *
     * @param obj Fill Me
     * @return Returns true if the attributes are
     */
    public boolean isSameAttribute(Attribute obj) {

        if (obj == null) {
            return false;
        }

        if (!(this.attributeId.equals(obj.getAttributeIdentifier()))) {
            return false;
        }

        EntityAttributes objIssuer = obj.getIssuer();
        if (this.issuer != null) {
            if (objIssuer == null) {
                return false;
            } else {
                if (!this.issuer.isSameEntity(objIssuer)) {
                    return false;
                }
            }
        } else {
            if (objIssuer != null) {
                return false;
            }
        }

        // valid from and valid to does not matter unless merging
        return valueMatches(obj);
    }

    /**
     * Returns true if one of the attribute value matches the value set.
     *
     * @param obj Fill Me
     * @return Fill Me
     */
    public boolean valueMatches(Attribute obj) {

        if (this.valueSet == null) {
            return obj.getAttributeValueSet() == null;
        } else {
            if (obj.getAttributeValueSet() == null) {
                return false;
            }

            // if the current attributes does not have any values, check if
            // compared one also does not have values.
            if ((this.valueSet.size() == 0)
                    && ((obj.getAttributeValueSet().size()) == 0)) {
                return true;
            }

            // Since even if one of the values matches, it is equal
            for (Object obj1 : obj.getAttributeValueSet()) {
                if (this.valueSet.contains(obj1)) {
                    return true;
                }
            }
            return false;
        }
    }

    public String toString() {

        StringBuffer str = new StringBuffer(this.attributeId.toString());
        str.append("\n Valid from: ");
        str.append(this.validFrom.getTime().toString());
        str.append("\n Valid till: ");
        if (this.validTill != null) {
            str.append(this.validTill.getTime().toString());
        } else {
            str.append("infinity");
        }
        str.append("\n Issuer: ");
        str.append(this.issuer);
        if (this.valueSet != null) {
            str.append("\n Values:\n\t");
            for (Object aValueSet : this.valueSet) {
                str.append(aValueSet);
                str.append("\n\t");
            }
        }
        return str.toString();
    }

    /**
     * Merges the values in the attibute.  Does not check if the
     * attributes match, use equals() for that. The merge is
     * restrictive with time. If the new attribute has a valid
     * from after current one, overwrite. If new attribute has a valid
     * to before current one, overwrite.
     *
     * @param attribute Fill Me
     */
    public void merge(Attribute<T> attribute) {

        if (attribute == null) {
            return;
        }

        // if attribute exist in map, but the localValueSet being
        // added is null,no point adding it
        Set<T> localValueSet = attribute.getAttributeValueSet();
        if (localValueSet != null) {
            // merge valid to and valid from
            Calendar newValidFrom = attribute.getValidFrom();
            if (newValidFrom.after(this.validFrom)) {
                this.validFrom = newValidFrom;
            }

            Calendar newValidTill = attribute.getValidTill();
            if ((newValidTill != null) && (newValidTill.before(this.validTill))) {
                this.validTill = newValidTill;
            }

            //merge values
            for (T aLocalValueSet : localValueSet) {
                addAttributeValue(aLocalValueSet);
            }
        }
    }

    /**
     * Returns true if the attribute has same issuer.
     *
     * @param attribute Fill Me
     * @return Fill Me
     */
    @SuppressWarnings("unused")
    public boolean isSameIssuer(Attribute attribute) {

        return attribute != null && !this.issuer.equals(attribute.getIssuer());

    }
}
