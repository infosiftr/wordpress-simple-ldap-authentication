=== Simple LDAP Authentication ===
Contributors: redgecko
Tags: authentication, ldap, login
Requires at least: 2.7
Tested up to: 2.7.1
Stable tag: 1.0.4

Authenticates users through LDAP.

== Description ==

This plugin allows WordPress to authenticate users against an LDAP.
To tell the truth, this is a hard modified version of [Active Directory Authentication](http://wordpress.org/extend/plugins/active-directory-authentication/) plugin.

Active Directory Authentication plugin and it's back-end ([adLDAP](http://adldap.sourceforge.net/)) require AD domain, in contrast, this plugin only needs LDAP server.

It is very easy to set up. Just activate the plugin, type in a LDAP server, and you're done.

= How to use =

You can use this plugin in a few different ways.

1. You can create WordPress accounts which match the names of your LDAP accounts, and create these users from within the WordPress Users panel. Only the users you create in WordPress will be able to log in.

2. You can tick a checkbox so that anyone who can authenticate via LDAP can log on. A WordPress account will be automatically created for the user if one does not already exist, with the default user role.

3. You can list the names of LDAP groups who you want to allow to log on to WordPress. For each group in LDAP, you can specify a corresponding WordPress user role.

You can also combine the above however you like.

= Version History =

* 1.0.4
   * Add `Role Equivalent Groups Editor' GUI.
   * Add reset button to initialize the options.
   * Add support to anonymous LDAP bind for user ID searching.
* 1.0.3
   * Fixed debug log message.
* 1.0.2
   * Fixed a bug that user ID filter didn't work.
* 1.0.1
   * Update readme.txt.
   * Add screenshots.
* 1.0
   * Initial release.

== Installation ==

1. Login as an existing user, such as admin.
2. Upload the folder named `simple-ldap-authentication` to your plugins folder, usually `wp-content/plugins`.
3. Activate the plugin on the Plugins screen.
4. Enable the "[Admin SSL](http://wordpress.org/extend/plugins/admin-ssl-secure-admin/)" plugin (or anything that redirects the logon page to an SSL connection) so that your passwords are not sent in cleartext.
   * If the version of Admin SSL is 1.4.1, you should apply [the redirection bug patch](http://wordpress.org/support/topic/267385?replies=1).

Note: This plugin has only been tested with WordPress 2.7.1 and above, and I do not think it will work on older versions of WordPress.

== Frequently Asked Questions ==

= This plugin supports Active Directory? =

No.
This plugin only supports LDAP bind.

= Can I use SSL on LDAP connection? =

Yes.
You can enable SSL connection in the option page.

= Can I customize LDAP search filter? =

Yes.
You can customize the search filters (user ID and group) in the option page.

= How do I use debug mode? =

This plugin has a built-in debug mode.
When `WP_DEBUG` is enabled in `wp-config.php`, it will turn on the notices that some authenticatin information are added on the log entry.
If you don't know how to define the constant, see [WordPress document](http://codex.wordpress.org/Editing_wp-config.php#Debug).

== Screenshots ==

1. The administration page under Settings -> Simple LDAP Authentication
2. Role Equivalent Groups Editor in the option page.
3. This plugin supports i18n. Japanese example.
