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

package org.globus.crux.security.attributes;

import java.net.URI;
import java.net.URISyntaxException;

public class Constants {

    /**
     * AttributeBase id for attribute that contains current axis message context
     */
    public static final URI ENVIRONMENT_ATTRIBUTE_URI;
    /**
     * AttributeBase id for attribute that contains container id.
     */
    public static final URI CONTAINER_ATTRIBUTE_URI;
    /**
     * AttributeBase id for attribute that contains the service endpoint.
     */
    public static final URI SERVICE_ATTRIBUTE_ID_URI;
    /**
     * AttributeBase id for attribute that contains the operation invoked.
     */
    public static final URI OPERATION_ATTRIBUTE_ID_URI;
    /**
     * AttributeBase id for string data type.
     */
    public static final URI STRING_DATATYPE_URI;
    /**
     * Data type for javax.security.auth.Subject
     */
    public static final URI SUBJECT_DATATYPE_URI;
    /**
     * Data type for org.apache.axis.MessageContext
     */
    public static final URI ENVIRONMENT_DATATYPE_URI;
    /**
     * Data type for set containing java.security.Principal
     */
    public static final URI PRINCIPAL_DATATYPE_URI;
    /**
     * AttributeBase id for attrbute containing subject
     */
    public static final URI SUBJECT_ATTRIBUTE_ID;
    /**
     * AttributeBase id for attrbute containing java.security.Principal
     */
    public static final URI PRINCIPAL_ATTRIBUTE_ID;
    /**
     * AttributeBase id for attribute containing SAML Authorization
     * Decision Statements.
     */
    public static final URI SAML_AUTHZ_DECISION_ATTRIBUTE_ID;
    /**
     * Data type SAML Authorization Decision Statements.
     */
    public static final URI SAML_AUTHZ_DECISION_DATA_TYPE;
    /**
     * Data type for parameter path representation. The value will be an array
     * of QName objects.
     */
    public static final URI PARAMETER_PATH_DATA_TYPE;
    /**
     * Permit override algorithm, that uses delegation of rights,
     * implemented by
     * org.globus.security.authorization.providers.PermitOverrideAlg
     */
    public static final String PERMIT_OVERRIDE_ALG = "PermitOverride";
    /**
     * First applicable algorithm, implemented by
     * org.globus.security.authorization.providers.FirstApplicableAlg
     */
    public static final String FIRST_APPLICABLE_ALG = "FirstApplicable";
    /**
     * Parameter name used in the ChainConfig object which contains
     * the parameter configured for the interceptor, as org.w3c.dom.Element
     */
    public static final String PARAMETER_OBJECT_NAME = "parameterObject";

// All methods are as the java bindings are (not as per WSDL)
    public static final String GET_RP_METHOD = "getResourceProperty";

    public static final String GET_MULTIPLE_RPS_METHOD =
            "getMultipleResourceProperties";

    public static final String SET_RP_METHOD = "setResourceProperties";

    static {

        try {
            STRING_DATATYPE_URI =
                    new URI("http://www.w3.org/2001/XMLSchema#string");
            PRINCIPAL_DATATYPE_URI =
                    new URI("urn:globus:4.0:datatype:java:set:principal");
            SUBJECT_DATATYPE_URI =
                    new URI("urn:globus:4.0:datatype:java:subject");
            ENVIRONMENT_DATATYPE_URI =
                    new URI("urn:globus:4.0:datatype:environment:context-map");
            CONTAINER_ATTRIBUTE_URI =
                    new URI("urn:globus:4.0:container:container-id");
            ENVIRONMENT_ATTRIBUTE_URI =
                    new URI("urn:globus:4.0:environment:context-map");
            SERVICE_ATTRIBUTE_ID_URI =
                    new URI("urn:globus:4.0:container:service-name");
            OPERATION_ATTRIBUTE_ID_URI =
                    new URI("urn:globus:4.0:container:operation-name");
            PRINCIPAL_ATTRIBUTE_ID =
                    new URI("urn:oasis:names:tc:xacml:1.0:subject:subject-id");
            SUBJECT_ATTRIBUTE_ID =
                    new URI("urn:globus:4.0:subject");
            SAML_AUTHZ_DECISION_DATA_TYPE =
                    new URI("urn:globus:4.0:datatype:saml:authzDecision");
            PARAMETER_PATH_DATA_TYPE =
                    new URI("urn:globus:4.0:datatype:java:array-of-qname");
            SAML_AUTHZ_DECISION_ATTRIBUTE_ID =
                    new URI("urn:globus:4.0::saml:authzDecision");
        } catch (URISyntaxException exp) {
            throw new RuntimeException(exp.getMessage());
        }
    }
}
