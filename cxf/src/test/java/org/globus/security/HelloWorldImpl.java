package org.globus.security;


import javax.jws.WebParam;
import javax.jws.WebService;


@WebService(targetNamespace = "http://www.globus.org/hello", name = "Hello_PortType",
        portName = "Hello_Port", serviceName = "Hello_Service",
        endpointInterface = "org.globus.security.HelloPortType")
public class HelloWorldImpl implements HelloPortType {


    public String sayHello(@WebParam(partName = "firstName", name = "firstName",
            targetNamespace = "") String firstName) {
        return "Hello, " + firstName;
    }
}
