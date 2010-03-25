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
package org.globus.crux.security.attributes;

import org.globus.util.I18nUtil;

/**
 * Stores a collection of IdentityAttributes. See AttributeCollection.
 */

public class IdentityAttributeCollection extends AttributeCollection {

    /**
	 * 
	 */
	private static final long serialVersionUID = 5475213179019500601L;
	private static I18nUtil i18n =
            I18nUtil.getI18n("org.globus.security.authorization.errors",
                    Attribute.class.getClassLoader());

    protected String getDescription() {
        return "Identity AttributeBase Collection";
    }

    public void add(Attribute<?> attribute) {

        if (!attribute.isIdentityAttribute()) {
            String err = i18n.getMessage("onlyIdenAttr");
            throw new IllegalArgumentException(err);
        }

        super.add(attribute);
    }

    public void addAll(AttributeCollection attrCollection) {

        if (!(attrCollection instanceof IdentityAttributeCollection)) {
            String err = i18n.getMessage("onlyIdenAttr");
            throw new IllegalArgumentException(err);
        }

        super.addAll(attrCollection);
    }
}
