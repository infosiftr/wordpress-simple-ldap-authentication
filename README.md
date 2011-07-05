# Simple LDAP Authentication
## Original Description

From http://wordpress.org/extend/plugins/simple-ldap-authentication/:

> This plugin allows WordPress to authenticate users against an LDAP. To tell the truth, this is a hard modified version of [Active Directory Authentication](http://wordpress.org/extend/plugins/active-directory-authentication/) plugin.
>
> Active Directory Authentication plugin and it's back-end ([adLDAP](http://adldap.sourceforge.net/)) require AD domain, in contrast, this plugin only needs LDAP server.
>
> It is very easy to set up. Just activate the plugin, type in a LDAP server, and you're done.

## Enhancements

Modified to work in a "MU" environment instead.  Eventually plan to add conditionals so that it works in a single site install again, but for now it's only tested in a multi-site environment.

Also, it has been modified to properly support XMLRPC authentication without requiring any hacks to Wordpress itself (upgrading use of the `wp_authenticate` action to use the `authenticate` filter instead).
