# Simple LDAP Authentication
## Original Description

From <http://wordpress.org/extend/plugins/simple-ldap-authentication/>:

> This plugin allows WordPress to authenticate users against an LDAP. To tell the truth, this is a hard modified version of [Active Directory Authentication](http://wordpress.org/extend/plugins/active-directory-authentication/) plugin.
>
> Active Directory Authentication plugin and it's back-end ([adLDAP](http://adldap.sourceforge.net/)) require AD domain, in contrast, this plugin only needs LDAP server.
>
> It is very easy to set up. Just activate the plugin, type in a LDAP server, and you're done.

## Enhancements

Modified to properly work in a multi-site install as well as a single-site install.  Eventually may add support for site-specific user specification, but that would be a long ways down the road, especially since we don't currently need it.  Suggestions/patches welcome. ;)

Also, it has been modified to properly support XMLRPC authentication without requiring any hacks to Wordpress itself (upgrading use of the `wp_authenticate` action to use the `authenticate` filter instead).

## Install

For single-site installs, just `git clone` into the `wp-content/plugins` directory, then enter the administration dashboard to enable (example: `mkdir -p wp-content/plugins && cd wp-content/plugins && git clone git://github.com/infosiftr/wordpress-simple-ldap-authentication.git simple-ldap-authentication`).

For multi-site installs, `git clone` into the `wp-content/mu-plugins` directory (create if necessary), and then symlink the php file up a level (example: `mkdir -p wp-content/mu-plugins && cd wp-content/mu-plugins && git clone git://github.com/infosiftr/wordpress-simple-ldap-authentication.git simple-ldap-authentication && ln -s simple-ldap-authentication/simple-ldap-authentication.php .`).
