Shield Kerberos Realm
=====================

[![Build Status](https://travis-ci.org/robertvolkmann/elasticsearch-shield-kerberos-realm.svg?branch=master)](https://travis-ci.org/robertvolkmann/elasticsearch-shield-kerberos-realm)
[![codecov](https://codecov.io/gh/robertvolkmann/elasticsearch-shield-kerberos-realm/branch/master/graph/badge.svg)](https://codecov.io/gh/robertvolkmann/elasticsearch-shield-kerberos-realm)
[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

Kerberos/SPNEGO custom realm for Elasticsearch X-Pack 5.0.2.  
Authenticate HTTP requests via Kerberos/SPNEGO.
Transport requests are not yet supported.

### License
Apache License Version 2.0

### Features

* Kerberos/SPNEGO REST/HTTP authentication
* No JAAS login.conf required
* No external dependencies

### Prerequisites

* Elasticsearch 5.0.2
* X-Pack Plugin 5.0.2
* Kerberos Infrastructure (ActiveDirectory, MIT, Heimdal, ...)

### Build and install latest
    $ git clone https://github.com/robertvolkmann/elasticsearch-shield-kerberos-realm.git
    $ mvn package
    $ bin/x-pack/extension install file:///path/to/target/release/elasticsearch-shield-kerberos-realm-2.4.4.zip

### Configuration

Configuration is done in elasticsearch.yml

    shield.authc.realms.kerberos:
        type: kerberos
        order: 0
        acceptor_principal: HTTP/localhost@REALM.COM
        files:
            acceptor_keytab: relative/path/to/server.keytab
            krb5_conf: relative/path/to/krb5.conf
        roles.user_role.0: user@REALM.com

* ``acceptor_principal`` - Acceptor (Server) Principal name, must be present in acceptor_keytab file
* ``acceptor_keytab`` - The relative path to the keytab where the acceptor_principal credentials are stored.
* ``krb5_conf`` - The relative path to krb5.conf file.
* ``roles`` - Roles which should be assigned to the initiator (the user who's logged in)
