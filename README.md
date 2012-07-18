kohana-ldap
================

LDAP module for Kohana 3.

Requirements
------------

You have to enable the PHP LDAP module.

How to use the authentication driver ?
--------------------------------------

Take a look at the file `config/auth-sample.php`. You could define several LDAP
servers, and specified an array into `order` parameter to configure in which
order servers are used during authentication.

