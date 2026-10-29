<?php
/**
 * Constants stubbed for PHPStan (defined in email-auth.php at runtime).
 *
 * @package Email Auth
 */

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/wordpress-root/' );
}

if ( ! defined( 'EAUTH_PLUGIN_FILE' ) ) {
	define( 'EAUTH_PLUGIN_FILE', dirname( __DIR__ ) . '/email-auth.php' );
}

if ( ! defined( 'EAUTH_PLUGIN_VERSION' ) ) {
	define( 'EAUTH_PLUGIN_VERSION', '1.5.1' );
}

if ( ! defined( 'EAUTH_DKIM_SELECTOR_REGEX' ) ) {
	define( 'EAUTH_DKIM_SELECTOR_REGEX', '/^[a-zA-Z0-9-._]+$/' );
}

if ( ! defined( 'EAUTH_PRIVATE_KEYS' ) ) {
	define( 'EAUTH_PRIVATE_KEYS', [] );
}

if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
	define( 'HOUR_IN_SECONDS', 3600 );
}
