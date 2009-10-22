package org.globus.security.spring.handlers;

import org.globus.schemas.security.ProxyTrustManager;
import org.globus.security.provider.PKITrustManager;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Oct 22, 2009
 * Time: 7:32:37 AM
 * To change this template use File | Settings | File Templates.
 */
public class GlobusTrustManagerFactoryDefinitionParser extends AbstractSingleBeanDefinitionParser {
    private JAXBContext jaxbContext;

    private JAXBContext getJaxbContext() throws JAXBException {
        return ((jaxbContext != null) ? jaxbContext :
                JAXBContext.newInstance("org.globus.schemas.security"));
    }

    @Override
    protected Class getBeanClass(Element element) {
        return PKITrustManager.class;
    }

    @Override
    protected void doParse(Element element, BeanDefinitionBuilder beanDefinitionBuilder) {
        try {
            ProxyTrustManager tmConfig = (ProxyTrustManager) getJaxbContext().createUnmarshaller().unmarshal(element);

            tmConfig.getId();
        } catch (JAXBException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }


    }


}
