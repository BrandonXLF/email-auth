<?php
/**
 * Common functions used by the Email Auth plugin.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Get the email domain for the current WordPress installation.
 *
 * @return string The email domain.
 */
function get_domain() {
	$domain = wp_parse_url( network_home_url(), PHP_URL_HOST );

	if ( null !== $domain && str_starts_with( $domain, 'www.' ) ) {
		$domain = substr( $domain, 4 );
	}

	return $domain;
}

/**
 * Get the known private keys from storag.
 */
function get_keys() {
	if ( file_exists( ABSPATH . '/eauth-keys.php' ) ) {
		include ABSPATH . '/eauth-keys.php';
	}

	return defined( constant_name: 'EAUTH_PRIVATE_KEYS' ) ? EAUTH_PRIVATE_KEYS : [];
}

/**
 * Save the given of private keys.
 *
 * @param array[string]string $keys The private keys.
 */
function save_keys( $keys ) {
	// Not used for debugging.
	// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export
	$str_keys = var_export( $keys, true );

	require_once ABSPATH . 'wp-admin/includes/file.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';

	$filesystem = new \WP_Filesystem_Direct( false );
	$filesystem->put_contents(
		ABSPATH . '/eauth-keys.php',
		<<<PHP
		<?php
		/**
		 * Private DKIM keys for the Email Auth plugin.
		 *
		 * @package Email Auth
		*/

		if ( ! defined( 'ABSPATH' ) ) {
			exit;
		}

		define('EAUTH_PRIVATE_KEYS', $str_keys);
		PHP,
		0640
	);
}
