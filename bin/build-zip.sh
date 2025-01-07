#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TOP_DIR=$( dirname -- SCRIPT_DIR )
VERSION=$( grep -oP " \* Version: *\K.+" $TOP_DIR/email-auth.php )

mv vendor vendor-backup
composer install --no-dev

cd $TOP_DIR
zip -r email-auth.$VERSION.zip admin includes vendor LICENSE readme.txt email-auth.php uninstall.php

rm -r vendor
mv vendor-backup vendor
