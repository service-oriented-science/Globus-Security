package org.globus.crux.main;

import org.globus.security.util.SSLConfigurator;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

@Test
public class TestJettyLoader {
	ApplicationContext context;

	@BeforeClass
	public void setup() {
		context = new ClassPathXmlApplicationContext("context.xml");
		SSLConfigurator config = context.getBean(SSLConfigurator.class);
		System.out.println(config.getCrlStore());
	}

	public void runTest() {

	}

}
