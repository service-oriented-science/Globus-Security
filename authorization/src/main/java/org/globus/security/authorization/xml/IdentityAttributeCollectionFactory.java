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

package org.globus.security.authorization.xml;

import java.util.List;

import org.globus.security.authorization.Attribute;
import org.globus.security.authorization.IdentityAttributeCollection;
import org.springframework.beans.factory.FactoryBean;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 26, 2010
 * Time: 3:15:23 PM
 * To change this template use File | Settings | File Templates.
 */
public class IdentityAttributeCollectionFactory implements FactoryBean<IdentityAttributeCollection> {
    private List<Attribute<?>> attributes;

    public IdentityAttributeCollection getObject() throws Exception {
        IdentityAttributeCollection collection = new IdentityAttributeCollection();
//        if (IAttributes != null) {
//            for (Attribute attribute : IAttributes) {
//                collection.add(attribute);
//            }
//        }
        return collection;
    }

    public Class<? extends IdentityAttributeCollection> getObjectType() {
        return IdentityAttributeCollection.class;
    }

    public boolean isSingleton() {
        return true;
    }

    public List<Attribute<?>> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<Attribute<?>> IAttributes) {
        this.attributes = IAttributes;
    }
}
