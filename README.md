# Email Auth - DKIM, SPF, DMARC, Bounce Address, From Address

**Configure the DKIM selector, SPF, DMARC, bounce address, from address, and reply-to address of emails sent by WordPress.
**

<a href="https://wordpress.org/plugins/email-auth/">WordPress.org listing</a>

## Description

Email Auth allows you to configure the DKIM selector, SPF, DMARC, bounce address, from address, and reply-to address of emails sent by WordPress through the default PHPMailer.

## Installation

### Requirements

* WordPress 4.6 or newer
* PHP 7.0 or greater is required (PHP 8.0 or greater is recommended)

### Steps

1. Upload this folder to your plugin directory (`wp-content/plugins`)
2. Activate the plugin through the "Plugins" menu in WordPress

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
