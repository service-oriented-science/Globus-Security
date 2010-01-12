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
package org.globus.security.authorization.util;

import java.util.List;

import org.globus.security.authorization.EntityAttributes;

/**
 * Fill Me
 */
public final class AttributeUtil {

    private AttributeUtil() {
        //this should not be initialized.
    }

    /**
     * Fill Me
     *
     * @param attributeList Fill Me
     * @param entityAttr Fill Me
     * @return Fill Me
     */
    public static EntityAttributes getMatchedEntity(List attributeList, EntityAttributes entityAttr) {

        if ((attributeList == null) || (entityAttr == null)) {
            return null;
        }

        for (Object anAttributeList : attributeList) {
            EntityAttributes retAttr = (EntityAttributes) anAttributeList;
            if (retAttr.isSameEntity(entityAttr)) {
                return retAttr;
            }
        }
        return null;
    }
}
