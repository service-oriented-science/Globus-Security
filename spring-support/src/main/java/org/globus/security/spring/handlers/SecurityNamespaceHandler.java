package org.globus.security.spring.handlers;

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Oct 21, 2009
 * Time: 2:42:12 PM
 * To change this template use File | Settings | File Templates.
 */
public class SecurityNamespaceHandler extends NamespaceHandlerSupport {
    public void init() {
        registerBeanDefinitionParser("socketFactory", new SSLSocketFactoryDefinitionParser());
        registerBeanDefinitionParser("keyStore", new JKSDefinitionParser());
        registerBeanDefinitionParser("proxyTrustManager", new GlobusTrustManagerFactoryDefinitionParser());
    }
}
