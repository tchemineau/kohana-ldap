kohana-auth-ldap
================

LDAP authentication driver for Kohana 3 authentication module.

Requirements
------------

You have to enable the PHP LDAP module.

How to use this driver ?
------------------------

Take a look at the file `config/auth-sample.php`. You could define several LDAP
servers, and specified an array into `order` parameter to configure in which
order servers are used during authentication.

