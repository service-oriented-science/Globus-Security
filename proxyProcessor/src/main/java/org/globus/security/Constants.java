/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.security;

import org.bouncycastle.asn1.DERObjectIdentifier;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class Constants {

    public enum CertificateType {

        CA, EEC, GSI_2_PROXY, GSI_2_LIMITED_PROXY, GSI_3_LIMITED_PROXY,
        GSI_3_RESTRICTED_PROXY, GSI_3_INDEPENDENT_PROXY,
        GSI_3_IMPERSONATION_PROXY,
        GSI_4_LIMITED_PROXY, GSI_4_RESTRICTED_PROXY, GSI_4_INDEPENDENT_PROXY,
        GSI_4_IMPERSONATION_PROXY
    }

    public static final DERObjectIdentifier PROXY_OID
            = new DERObjectIdentifier("1.3.6.1.5.5.7.1.14");
    public static final DERObjectIdentifier PROXY_OLD_OID
            = new DERObjectIdentifier("1.3.6.1.4.1.3536.1.222");

}
