Current Code Base
*****************

* Attempt here is to use as much of the native java classes as possible
* CertStore assumes only CRLs and TrustAnchors. This code base provides a Globus
Provider for a FileBased CertStore that read certificates (.digit) and CRLs (.r<digit>)
from a directory
* Signing policy is processed as a separate interface. This could also be allowed
a provider interface like the CertStore. The implementation that will be provided
will be for file based signing policy and based on the certstore provider.
* The above separation is to allow use of standard CertStores if signing policy
is not required by any application
* Proxy Path validation is implemented as a provider and uses standard interfaces.

The code itself is alpha quality and tests from current CoG JGlobus have been ported over. No new tests have been written.

VOMS code
+++++++++

* Code: https://svn.forge.cnaf.infn.it/svn/voms/voms/branches/voms-1-9-series
* General Comments:
++++++++++++++++++
** C and Java code is combined in same module.
** Build system is make/configure. The Ant file depends on larger gLite build.
** There are no unit tests. The only way to test this is to set up a VOMS server
and client and do end to end test. Apparently only four tests exercise the Java
code and rest the C code.
** Code coupled with VOMS and forces use of VOMS configuration
** No interfaces to provide any pluggability to developer leveraging this module.
** Varaible names not meeting Java coding standards
** Commented out code
** BC installation all over the library.
** No separate documentaiton for the code base
* PKIStore
++++++++++
** Timer based loading of certificate extensions, rather than upon change. Error
prone and requires the API user to invoke operations to stop timers.
** Tightly coupled with VOMS specifics
* PKIVerifier
+++++++++++++
* TODO: Check validation against what is done in CoG
* Open issue of path length constraint not respected
* limited proxy checks not completed implemented
* Signing Policy
++++++++++++++++
* What is the grammar that has been implemented? Apparently one mentioned by
IGTF. Yet to find link.
* TODO: Check signing policy againt what is done in CoG
* Questions
+++++++++++
* Where are the tomcat valves that set up use of this trust manager?
* Why not try to reuse the Java 5 cert package interfaces? CertStore cannot be
reused because of SigningPolicy issues, but CertPathValidator seems to be
 sufficiently abstract to configure custom pieces.
 http://java.sun.com/j2se/1.5.0/docs/guide/security/certpath/CertPathProgGuide.html
* Are CRLS downloaded from a *crl_url file? Or is that out of scope?

Goals
*****

* Implementation of X509TrustManager to support
** Certificate signature, time validation
** Trust root validateion
** Signing policy enforcement
** CRL enforcement (should this include downloading of CRLS from a *crl_url file?)
** Allow custom validation of extensions
*** X.509 Proxy Certificate processing and verification
*** VOMS AC processing verification 

