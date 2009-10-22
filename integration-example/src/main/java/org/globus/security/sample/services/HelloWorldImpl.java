package org.globus.security.sample.services;



import com.ecerami.wsdl.helloservice.HelloPortType;

import javax.jws.WebParam;
import javax.jws.WebService;

@WebService(targetNamespace = "http://www.ecerami.com/wsdl/HelloService.wsdl", name = "Hello_PortType",
portName = "Hello_Port", serviceName = "Hello_Service", endpointInterface = "com.ecerami.wsdl.helloservice.HelloPortType")
public class HelloWorldImpl implements HelloPortType {

    public String sayHello(@WebParam(partName = "firstName", name = "firstName", targetNamespace = "") String firstName) {
        return "Hello, " + firstName;
    }
}
