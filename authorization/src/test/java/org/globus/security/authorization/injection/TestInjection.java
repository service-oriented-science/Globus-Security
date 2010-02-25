package org.globus.security.authorization.injection;

import org.globus.security.authorization.BaseConfigurator;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

@Test
public class TestInjection {

	AnnotationConfigApplicationContext context;
	
	@BeforeClass
	public void setup() throws Exception {
		context = new AnnotationConfigApplicationContext();
		context.register(BaseConfigurator.class);
		context.register(BaseTestConfiguration.class);
		context.refresh();
		context.start();		
	}
	
	public void test() throws Exception{
		SampleServiceForInjection service = context.getBean(SampleServiceForInjection.class);
		service.doSomthingWithContext();
	}
}
