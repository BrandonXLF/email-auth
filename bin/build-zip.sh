#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TOP_DIR=$( dirname -- SCRIPT_DIR )
VERSION=$( grep -oP " \* Version: *\K.+" $TOP_DIR/email-auth.php )

mv vendor vendor-backup
composer install --no-dev --optimize-autoloader

cd $TOP_DIR
cd ..
zip -0 -r email-auth/email-auth.$VERSION.zip email-auth/admin email-auth/includes \
	email-auth/vendor email-auth/LICENSE email-auth/readme.txt email-auth/email-auth.php \
	email-auth/uninstall.php email-auth/composer.json \
	-x **/bin

cd email-auth
rm -r vendor
mv vendor-backup vendor
