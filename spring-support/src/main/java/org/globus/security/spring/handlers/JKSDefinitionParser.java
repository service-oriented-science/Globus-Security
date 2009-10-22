package org.globus.security.spring.handlers;

import org.globus.security.spring.JKSFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.w3c.dom.Element;

import java.security.KeyStore;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Oct 21, 2009
 * Time: 3:35:39 PM
 * To change this template use File | Settings | File Templates.
 */
public class JKSDefinitionParser extends AbstractSingleBeanDefinitionParser {
    @Override
    protected Class getBeanClass(Element element) {
        return JKSFactory.class;
    }

    @Override
    protected void doParse(Element element, BeanDefinitionBuilder beanDefinitionBuilder) {
        String location = element.getAttribute("location");
        String password = element.getAttribute("password");
        beanDefinitionBuilder.addPropertyValue("location", location);
        beanDefinitionBuilder.addPropertyValue("password", password);        
    }
}
