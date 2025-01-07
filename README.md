# Email Auth - DKIM, SPF, DMARC, Bounce Address, From Address

**Configure the DKIM selector, SPF, DMARC, bounce address, from address, and reply-to address of emails sent by WordPress.**

<a href="https://wordpress.org/plugins/email-auth/">WordPress.org listing</a>

## Description

Email Auth allows you to configure the DKIM selector, SPF, DMARC, bounce address, from address, and reply-to address of emails sent by WordPress through the default PHPMailer.

### DKIM Selector

Create, upload, download, and delete private and public keys for use with DKIM with an intuitive interface.
Configure emails to use a DKIM selector and configure which domain should be used with DKIM.

### SPF

Create a new SPF record for your envelope domain, validate an existing record, or view recommendations for how to improve your SPF configuration.

### DMARC

Validate your DMARC DNS record settings and view comments about your current configuration.

### Bounce Address

Set your bounce address to ensure emails are being sent from the right domain to avoid having your emails rejected or marked as spam.

### From Address and Reply-To Address

Set the address and name emails are sent from along with the address replies should be sent to.

## Installation

### Requirements

* WordPress 4.6 or newer
* PHP 7.0 or greater is required (PHP 8.0 or greater is recommended)

### Steps

1. Upload this folder to your plugin directory (`wp-content/plugins`)
2. Activate the plugin through the "Plugins" menu in WordPress
3. Visit "Settings" > "Email Auth" to configure the plugin

## Developing

### Installing dependencies

Composer and npm are required to install dependencies. Once they are installed, run `composer install` and `npm install` to install dependencies.

### Code sniffing

#### PHP

Run `composer run phpcs` to run the code sniffer. Run `composer run phpcs:full` for a full breakdown of what errors occurred and `composer run phpcs:fix` to fix any auto-fixable errors.

#### JS

Run `npm run lint` to run the linter and `npm run lint:fix` to fix any auto-fixable errors.

### Creating ZIP archive

Run `bin/build-zip.sh` to create a ZIP archive of the plugin that is suitable to be uploaded to a WordPress site.

### Publishing

Run `bin/release-svn.sh` to create a release version and add it as a tag to SVN. Run `bin/update-svn-assets.sh` to update wordpress.org assets only. You can specify your SVN username with `--username USERNAME`.
