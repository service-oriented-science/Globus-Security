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

import org.globus.security.authorization.util.I18nUtil;

/**
 * Data type with members that uniquely identify an attribute
 */
public class AttributeIdentifier implements Serializable {

    private static I18nUtil i18n =
            I18nUtil.getI18n("org.globus.security.authorization.errors",
                    AttributeIdentifier.class.getClassLoader());

    private URI attributeId;
    private URI dataType;
    private boolean identityAttibute;

    private AttributeIdentifier() {
    }

    /**
     * Constructs a non-identity atttibute
     *
     * @param id        Attribute ID URI
     * @param dataType_ Datatype of Attribute
     */
    public AttributeIdentifier(URI id, URI dataType_) {
        this(id, dataType_, false);
    }

    /**
     * @param id        Attribute ID URI
     * @param dataType_ Datatype of Attribute
     * @param identity  If set to true, an identity attribute it created. If
     *                  not, a non-identity attribute is created.
     */
    public AttributeIdentifier(URI id, URI dataType_, boolean identity) {
        if (id == null) {
            String err = i18n.getMessage("attrIdNotNull");
            throw new IllegalArgumentException(err);
        }

        if (dataType_ == null) {
            String err = i18n.getMessage("dataTypeNotNull");
            throw new IllegalArgumentException(err);
        }

        this.attributeId = id;
        this.dataType = dataType_;
        this.identityAttibute = identity;

    }

    /**
     * Returns attribute Id
     */
    public URI getAttributeId() {
        return this.attributeId;
    }

    /**
     * Returns data type
     */
    public URI getDataType() {
        return this.dataType;
    }

    /**
     * Returns if the attribute is an identity attribute
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

        if (!this.attributeId.equals(obj.getAttributeId())) {
            return false;
        }

        if (!this.dataType.equals(obj.getDataType())) {
            return false;
        }

        if (this.identityAttibute != obj.isIdentityAttribute()) {
            return false;
        }

        return true;
    }

    public int hashCode() {
        return this.attributeId.hashCode() + this.dataType.hashCode()
                + Boolean.valueOf(this.identityAttibute).hashCode();
    }

    public String toString() {

        return " Attribute Id: " + this.attributeId + "\n Datatype: "
                + this.dataType + "\n Identity: "
                + Boolean.valueOf(this.identityAttibute);
    }
}
