package org.globus.security.spring.handlers;

import org.globus.security.spring.GlobusSocketFactoryFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;

import javax.net.ssl.SSLSocketFactory;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Oct 21, 2009
 * Time: 2:43:12 PM
 * To change this template use File | Settings | File Templates.
 */
public class SSLSocketFactoryDefinitionParser extends AbstractSingleBeanDefinitionParser {

    @Override
    protected Class getBeanClass(Element element) {
        return GlobusSocketFactoryFactory.class;
    }

    @Override
    protected void doParse(Element element, BeanDefinitionBuilder beanDefinitionBuilder) {
        if(element.getAttribute("provider") != null){
            String provider = element.getAttribute("provider");
            beanDefinitionBuilder.addPropertyValue("provider", provider);
        }
        if(element.getAttribute("protocol") != null){
            String protocol = element.getAttribute("protocol");
            beanDefinitionBuilder.addPropertyValue("protocol", protocol);
        }

    }
}
