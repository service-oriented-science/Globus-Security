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
import java.net.URI;

import org.globus.util.I18n;

/**
 * Data type with members that uniquely identify an attribute
 */
public class AttributeIdentifier implements Serializable {

    /**
	 * 
	 */
	private static final long serialVersionUID = -7963560462839338318L;

	private static I18n i18n =
            I18n.getI18n("org.globus.security.authorization.errors",
                    AttributeIdentifier.class.getClassLoader());

    private URI attributeId;
    private URI dataType;
    private boolean identityAttibute;

    @SuppressWarnings("unused")
    private AttributeIdentifier() {
    }

    /**
     * Constructs a non-identity atttibute
     *
     * @param id        AttributeBase ID URI
     * @param initDataType Datatype of AttributeBase
     */
    public AttributeIdentifier(URI id, URI initDataType) {
        this(id, initDataType, false);
    }

    /**
     * @param id        AttributeBase ID URI
     * @param initDataType Datatype of AttributeBase
     * @param identity  If set to true, an identity attribute it created. If
     *                  not, a non-identity attribute is created.
     */
    public AttributeIdentifier(URI id, URI initDataType, boolean identity) {
        if (id == null) {
            String err = i18n.getMessage("attrIdNotNull");
            throw new IllegalArgumentException(err);
        }

        if (initDataType == null) {
            String err = i18n.getMessage("dataTypeNotNull");
            throw new IllegalArgumentException(err);
        }

        this.attributeId = id;
        this.dataType = initDataType;
        this.identityAttibute = identity;

    }

    /**
     * Returns attribute Id
     *
     * @return Fill Me
     */
    public URI getAttributeId() {
        return this.attributeId;
    }

    /**
     * Returns data type
     *
     * @return Fill Me
     */
    public URI getDataType() {
        return this.dataType;
    }

    /**
     * Returns if the attribute is an identity attribute
     *
     * @return Fill Me
     */
    public boolean isIdentityAttribute() {
        return this.identityAttibute;
    }

    /**
     * Returns true if the AttributeIdentifier is equal.
     */
    public boolean equals(Object object) {

        if (object == null) {
            return false;
        }

        if (!(object instanceof AttributeIdentifier)) {
            return false;
        }

        AttributeIdentifier obj = (AttributeIdentifier) object;

        return this.attributeId.equals(obj.getAttributeId()) && this.dataType.equals(obj.getDataType())
            && this.identityAttibute == obj.isIdentityAttribute();

    }

    public int hashCode() {
        return this.attributeId.hashCode() + this.dataType.hashCode()
                + Boolean.valueOf(this.identityAttibute).hashCode();
    }

    public String toString() {

        return " AttributeBase Id: " + this.attributeId + "\n Datatype: "
                + this.dataType + "\n Identity: "
                + this.identityAttibute;
    }
}
