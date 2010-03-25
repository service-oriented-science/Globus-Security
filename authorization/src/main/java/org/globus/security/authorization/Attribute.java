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

import java.io.Serializable;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.globus.util.I18n;

/**
 * Data type representing an attribute. Attribute is uniquely identified by
 * AttributeIdentifier. It has an issuer, validity time stamps and set of values
 * of same datatype (not ensured in code), without any duplicates.
 */
public class Attribute<T> implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -4003937239024876946L;

	private static I18n i18n = I18n.getI18n(
			"org.globus.security.authorization.errors", Attribute.class
					.getClassLoader());

	private Calendar validFrom;
	private Calendar validTill;
	private AttributeIdentifier attributeId = null;
	private Set<T> valueSet = null;
	private EntityAttributes issuer = null;

	public Attribute(AttributeIdentifier attributeId_,
			EntityAttributes issuer_, Calendar validFrom, Calendar validTill) {
		this(attributeId_, issuer_, validFrom, validTill, null);
	}

	/**
	 * Constructor
	 * 
	 * @param attributeId_
	 *            AttributeIdentifier object. Cannot be null
	 * @param issuer_
	 *            Issuer of asertion. If this is null, the framework assumes
	 *            that the container is the issuer. All PIPs must make sure that
	 *            this value it filled, if contiane should not be assumed to be
	 *            the owner.
	 * @param validFrom_
	 *            Time stamp from which attribute is valid. Cannot be null.
	 * @param validTill_
	 *            Time until which attribute is valid. Must beafter validFrom_
	 * @param values
	 *            Contents of this set are added as attribute values.
	 */
	public Attribute(AttributeIdentifier attributeId_,
			EntityAttributes issuer_, Calendar validFrom_, Calendar validTill_,
			Set<T> values) {

		if (attributeId_ == null) {
			String err = i18n.getMessage("attrIdNotNull");
			throw new IllegalArgumentException(err);
		}

		if (validFrom_ == null) {
			String err = i18n.getMessage("validFromNotNull");
			throw new IllegalArgumentException(err);
		}

		if ((validTill_ != null) && (validTill_.before(validFrom_))) {
			String err = i18n.getMessage("badValidTill");
			throw new IllegalArgumentException(err);
		}

		this.attributeId = attributeId_;
		this.issuer = issuer_;
		this.validFrom = validFrom_;
		this.validTill = validTill_;

		if (values != null) {
			this.valueSet = Collections.synchronizedSet(new HashSet<T>(values));
		}
	}

	/**
	 * Returns issuer of assertion.
	 */
	public EntityAttributes getIssuer() {
		return this.issuer;
	}

	/**
	 * Overwrites the existing collection of values, with this set.
	 */
	public void setAttributeValueSet(Set<T> values) {
		this.valueSet = Collections.synchronizedSet(new HashSet<T>(values));
	}

	/**
	 * Adds this object to the attribute value set.
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
	 */
	public Set<T> getAttributeValueSet() {
		return this.valueSet;
	}

	/**
	 * Returns AttributeIdentifier
	 */
	public AttributeIdentifier getAttributeIdentifier() {
		return this.attributeId;
	}

	/*
	 * Returns true of the attribute is an identity attribute.
	 */
	public boolean isIdentityAttribute() {
		return this.attributeId.isIdentityAttribute();
	}

	/**
	 * Returns timestamp from when this attribute is valid
	 */
	public Calendar getValidFrom() {
		return this.validFrom;
	}

	public Calendar getValidTill() {
		return this.validTill;
	}

	/**
	 * This method is used to compare if the attribute is semantically
	 * equivalent to the one passed as parameter and is a subjective comparison
	 * of the attributes.
	 * 
	 * The attributes are deemed the same if attributeId matches, issuer entity
	 * matches (refer <code>EntityAttributes.isSameEntity</code>) and atleast
	 * one value matches. Time stamps are ignored.
	 * 
	 * @return Returns true if the attributes are
	 * 
	 * */
	public boolean isSameAttribute(Attribute<?> obj) {

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
	 */
	public boolean valueMatches(Attribute<?> obj) {

		if (this.valueSet == null) {
			if (obj.getAttributeValueSet() != null) {
				return false;
			}
			return true;
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
			Iterator<?> iterator = obj.getAttributeValueSet().iterator();
			while (iterator.hasNext()) {
				Object obj1 = iterator.next();
				if (this.valueSet.contains(obj1)) {
					return true;
				}
			}
			return false;
		}
	}

	public String toString() {

		StringBuffer str = new StringBuffer(this.attributeId.toString());
		str.append("\n Valid from: " + this.validFrom.getTime().toString());
		str.append("\n Valid till: ");
		if (this.validTill != null) {
			str.append(this.validTill.getTime().toString());
		} else {
			str.append("infinity");
		}
		str.append("\n Issuer: " + this.issuer);
		if (this.valueSet != null) {
			str.append("\n Values:\n\t");
			Iterator<T> iterator = this.valueSet.iterator();
			while (iterator.hasNext()) {
				str.append(iterator.next() + "\n\t");
			}
		}
		return str.toString();
	}

	/**
	 * Merges the values in the attibute. Does not check if the attributes
	 * match, use equals() for that. The merge is restrictive with time. If the
	 * new attribute has a valid from after current one, overwrite. If new
	 * attribute has a valid to before current one, overwrite.
	 */
	public void merge(Attribute<T> attribute) {

		if (attribute == null) {
			return;
		}

		// if attribute exist in map, but the valueSet being
		// added is null,no point adding it
		Set<T> valueSet = attribute.getAttributeValueSet();
		if (valueSet != null) {
			// merge valid to and valid from
			Calendar newValidFrom = attribute.getValidFrom();
			if (newValidFrom.after(this.validFrom)) {
				this.validFrom = newValidFrom;
			}

			Calendar newValidTill = attribute.getValidTill();
			if ((newValidTill != null) && (newValidTill.before(this.validTill))) {
				this.validTill = newValidTill;
			}

			// merge values
			Iterator<T> it = valueSet.iterator();
			while (it.hasNext()) {
				addAttributeValue(it.next());
			}
		}
	}

	/**
	 * Returns true if the attribute has same issuer.
	 */
	public boolean isSameIssuer(Attribute<T> attribute) {

		if (attribute == null) {
			return false;
		}

		if (this.issuer.equals(attribute.getIssuer())) {
			return false;
		} else {
			return true;
		}
	}
}
