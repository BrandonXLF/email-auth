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
 * Get the known private keys from storage.
 *
 * @return array[string]string $keys The private keys.
 */
function get_keys() {
	if ( defined( 'EAUTH_PRIVATE_KEYS' ) ) {
		return EAUTH_PRIVATE_KEYS;
	}

	$keys_path = get_config_dir( 'dkim-keys.php', false );

	if ( file_exists( $keys_path ) ) {
		include $keys_path;
	}

	return defined( 'EAUTH_PRIVATE_KEYS' ) ? EAUTH_PRIVATE_KEYS : [];
}

/**
 * Save the given of private keys for subsequent page loads.
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

/**
 * Make a \Net_DNS2_Resolver instance with plugin-specific settings.
 *
 * @return \Net_DNS2_Resolver
 */
function get_net_dns2_resolver() {
	global $eauth_net_dns2_resolver;

	if ( ! ( $eauth_net_dns2_resolver instanceof \Net_DNS2_Resolver ) ) {
		$eauth_net_dns2_resolver = new \Net_DNS2_Resolver(
			[
				'nameservers' => [
					'1.1.1.1',
					'1.0.0.1', // Cloudflare DNS.
					'8.8.8.8',
					'8.8.4.4', // Google Public DNS.
					'208.67.222.222',
					'208.67.220.220', // OpenDNS.
				],
			]
		);
	}

	return $eauth_net_dns2_resolver;
}

/**
 * Get all OpenSSL errors in a presentable format.
 *
 * @param string $prefix The prefix to show before each error string.
 * @return string
 */
function get_openssl_errors( $prefix = '\n' ) {
	$out = '';

	// phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
	while ( $msg = openssl_error_string() ) {
		$out .= "{$prefix}OpenSSL error: $msg";
	}

	return $out;
}

/**
 * Create a common API response.
 *
 * @param string|bool $pass The pass status. Can be true, false, or "partial".
 * @param string|null $reason The reason for the failure.
 * @param array       $data Additional data to include in the response.
 * @return array{pass: string, reason: string}
 */
function api_response( $pass, $reason, &$data = [] ) {
	return [
		'pass'   => $pass,
		'reason' => $reason,
	] + $data;
}

/**
 * Create a common API pass response.
 *
 * @param string $partial True if the pass is only a partial pass.
 * @param array  $data Additional data to include in the response.
 * @return array{pass: string, reason: null}
 */
function api_pass( $partial, &$data = [] ) {
	return api_response( $partial ? 'partial' : true, null, $data );
}

/**
 * Create a common API failure response.
 *
 * @param string $reason The reason for the failure.
 * @param array  $data Additional data to include in the response.
 * @return array{pass: string, reason: string}
 */
function api_failure( $reason, &$data = [] ) {
	return api_response( false, $reason, $data );
}
