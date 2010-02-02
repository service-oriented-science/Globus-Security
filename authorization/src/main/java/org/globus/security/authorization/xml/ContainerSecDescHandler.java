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
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.NamespaceHandlerSupport;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Jan 26, 2010
 * Time: 12:57:39 PM
 * To change this template use File | Settings | File Templates.
 */
public class ContainerSecDescHandler extends NamespaceHandlerSupport {


    public void init() {
        registerBeanDefinitionParser("containerSecurityConfig", new SecurityDescriptorBeanParser());
    }

    private static class SecurityDescriptorBeanParser extends AbstractBeanDefinitionParser {


        @Override
        protected Class getBeanClass(Element element) {
            return SecurityDescriptor.class;
        }

        @Override
        protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder bean) {
            NodeList children = element.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                Node n = children.item(i);
                if (n.getNodeType() == Node.ELEMENT_NODE && n.getLocalName().equals("authzChain")) {
                    BeanDefinitionBuilder authzChainBuilder = BeanDefinitionBuilder.rootBeanDefinition(AuthZChain.class);
                    processAuthzChain((Element) n, parserContext, authzChainBuilder);
                    bean.addPropertyValue("authzChain", authzChainBuilder.getBeanDefinition());
                }
            }
        }

        private void processAuthzChain(Element element, ParserContext parserContext, BeanDefinitionBuilder bean) {
            NodeList children = element.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                Node n = children.item(i);
                if (n.getNodeType() == Node.ELEMENT_NODE) {
                    String name = n.getLocalName();

                    if ("bootstrapPips".equals(name) || "pips".equals(name) || "pdps".equals(name)) {
                        List list = parserContext.getDelegate().parseListElement((Element) n, bean.getBeanDefinition());
                        bean.addPropertyValue(name, list);
                    }
                }
            }
        }

        @Override
        protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) throws BeanDefinitionStoreException {
            return "SecurityDescriptor";
        }
    }
}
