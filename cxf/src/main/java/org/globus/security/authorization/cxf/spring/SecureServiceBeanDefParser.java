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

package org.globus.security.authorization.cxf.spring;

import org.globus.security.authorization.cxf.GlobusAuthzInvoker;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Feb 8, 2010
 * Time: 4:13:34 PM
 * To change this template use File | Settings | File Templates.
 */
public class SecureServiceBeanDefParser extends AbstractSingleBeanDefinitionParser {

    protected Class<GlobusAuthzInvoker> getBeanClass(Element element) {
        return GlobusAuthzInvoker.class;
    }


    @Override
    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        String ref = element.getAttribute("serviceObjectRef");
        if (ref != null && !ref.isEmpty()) {
            builder.addPropertyReference("serviceObject", ref);
        }
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element child = (Element) children.item(i);
                Object serviceObject = parserContext.getDelegate().parsePropertySubElement(child,
                        builder.getBeanDefinition());
                builder.addPropertyValue("serviceObject", serviceObject);
                break;
            }
        }
    }
}
