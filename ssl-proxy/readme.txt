To do:
======

* Test coverage for proxy credential handling classes from CoG
* Improve test coverage for keystore impl.
* Look at CoG patches since 1.7.0 was released and merge those features

For documentation:
==================

* The following error message from SSL handshake could also mean that the credentials were empty or no credentials were
 presented for handshake. "javax.net.ssl.SSLException: No available certificate or key corresponds to the SSL cipher
 suites which are enabled."
