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
 * Get the path of a config file for the current site.
 *
 * @param string $file The config file name.
 * @param bool   $make True if the path should be created if it does not exist.
 * @return string The path of the config file.
 */
function get_config_dir( $file = '', $make = true ) {
	$path = wp_upload_dir()['basedir'] . '/email-auth';

	if ( $make ) {
		wp_mkdir_p( $path );
	}

	if ( ! empty( $file ) ) {
		$path .= '/' . $file;
	}

	return $path;
}

/**
 * Get the path of the dkim-keys.php file.
 */

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
	$keys_path = get_config_dir( 'dkim-keys.php', false );

	if ( file_exists( $keys_path ) ) {
		include $keys_path;
	}

	return defined( constant_name: 'EAUTH_PRIVATE_KEYS' ) ? EAUTH_PRIVATE_KEYS : [];
}

/**
 * Save the given of private keys.
 *
 * @param array[string]string $keys The private keys.
 */
function save_keys( $keys ) {
	$keys_path = get_config_dir( 'dkim-keys.php' );

	if ( empty( $keys ) ) {
		wp_delete_file( $keys_path );
		return;
	}

	// Not used for debugging.
	// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export
	$str_keys = var_export( $keys, true );

	require_once ABSPATH . 'wp-admin/includes/file.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';

	$filesystem = new \WP_Filesystem_Direct( false );
	$filesystem->put_contents(
		$keys_path,
		"<?php
/**
 * Private DKIM keys for the Email Auth plugin.
 *
 * @package Email Auth
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define('EAUTH_PRIVATE_KEYS', $str_keys);
",
		0640
	);
}
