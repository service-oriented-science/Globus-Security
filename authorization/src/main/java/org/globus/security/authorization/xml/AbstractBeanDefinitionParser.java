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

import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParserDelegate;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import java.util.StringTokenizer;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 26, 2010
 * Time: 5:27:17 PM
 * To change this template use File | Settings | File Templates.
 */
public class AbstractBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    public static final String NAMESPACE_URI = "http://cxf.apache.org/schemas/configuration/cxf-beans";

    public static final String NAME_ATTR = "name";

    public static final String ABSTRACT_ATTR = "abstract";

    public static final String CREATED_FROM_API_ATTR = "createdFromAPI";

    @Override
    protected String resolveId(Element elem, AbstractBeanDefinition definition,
                               ParserContext ctx) throws BeanDefinitionStoreException {

// REVISIT: use getAttributeNS instead

        String id = getIdOrName(elem);
        String createdFromAPI = elem.getAttribute(CREATED_FROM_API_ATTR);

        if (null == id || "".equals(id)) {
            return super.resolveId(elem, definition, ctx);
        }

        if (createdFromAPI != null && "true".equals(createdFromAPI.toLowerCase())) {
            return id + getSuffix();
        }
        return id;
    }

    protected String getSuffix() {
        return "";
    }

    protected String getIdOrName(Element elem) {
        String id = elem.getAttribute(BeanDefinitionParserDelegate.ID_ATTRIBUTE);

        if (null == id || "".equals(id)) {
            String names = elem.getAttribute("name");
            if (null != names) {
                StringTokenizer st = new StringTokenizer(names, BeanDefinitionParserDelegate.BEAN_NAME_DELIMITERS);
                if (st.countTokens() > 0) {
                    id = st.nextToken();
                }
            }
        }
        return id;
    }
}
