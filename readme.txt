=== Email Auth - DKIM, SPF, DMARC, Bounce Address, From Address ===
Contributors: brandonxlf
Tags: email
Donate link: https://www.brandonfowler.me/donate/
Tested up to: 6.7
Stable tag: 1.2.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Configure the DKIM selector, SPF, DMARC, bounce address, from address, and reply-to address of emails sent by WordPress.

== Description ==

Email Auth allows you to configure the DKIM selector, SPF, DMARC, bounce address, from address, and reply-to address of emails sent by WordPress through the default PHPMailer. 

Configuring these email settings allows you to prevent attackers from spoofing emails from your domain and helps keep your emails out of the spam folder.

=  DKIM Selector =

Create, upload, download, and delete private and public keys for use with DKIM with an intuitive interface. Configure emails to use a DKIM selector and configure which domain should be used with DKIM.

= SPF =

Create a new SPF record for your envelope domain, validate an existing record, or view recommendations for how to improve your SPF configuration.

= DMARC =

Validate your DMARC DNS record settings and view comments about your current configuration.

= Bounce Address = 

Set your bounce address to ensure emails are being sent from the right domain to avoid having your emails rejected or marked as spam.

= From Address and Reply-To Address = 

Set the address and name emails are sent from along with the address replies should be sent to.

== External Services ==

This plugin connects to an online list from [publicsuffix.org](https://publicsuffix.org/) to determine which organizational domain should be searched when obtaining DMARC DNS records. For example, if the domain wordpress.brandonfowler.me does not have a DMARC record, then brandonfowler.me will be checked for a DMARC record. No user information is sent when requesting the list and its usage is subject to the [Mozilla Public License Version 2.0](https://mozilla.org/MPL/2.0/).

== Contribute ==

Check out [the GitHub repository](https://github.com/BrandonXLF/email-auth) to learn more about how you can contribute to the plugin's development.

== Installation ==

= Requirements =

* WordPress 6.0 or newer
* PHP 7.4 or greater is required (PHP 8.0 or greater is recommended)

= Steps =

1. Navigate to the "Add New Plugin" menu item
2. Click "Upload Plugin" and upload the zip file
3. Activate the plugin through the "Plugins" menu in WordPress
4. Visit "Settings" > "Email Auth" to configure the plugin

== Changelog ==

= 1.2.3 =

Improve input field labels on the options page

= 1.2.2 =

- Show OpenSSL errors on the options page
- Show issues with determining organizational domain
- Abort previous check request when a new one is made
- Run PHPMailer actions last
- Return unaltered from address properly when required

= 1.2.1 =

Show dynamic domain values for alignment mismatch

= 1.2.0 =

- Show relevant DNS domain for each test
- Reformat SPF section
- Prevent DKIM from loading unnecessarily
- Support entry concatenation for DMARC

= 1.1.0 =

- Separate SPF test results and validity results
- Show more details for failed DNS record fetches
- Improve comment formatting

= 1.0.0 =

Initial release.
