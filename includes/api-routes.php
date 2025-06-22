<?php
/**
 * API routes.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'EAUTH_API_PREFIX', 'eauth/v1' );
define( 'EAUTH_DOMAIN_IN_URL_REGEX', '[a-zA-Z0-9-._]+' ); // _ is widely supported

/**
 * Check if the current user can use the admin API.
 *
 * @return bool
 */
function rest_api_permission_callback() {
	return current_user_can( 'manage_options' );
}

register_rest_route(
	EAUTH_API_PREFIX,
	'/dkim/keys',
	[
		'methods'             => 'GET',
		'callback'            => function () {
			return array_keys( get_keys() );
		},
		'permission_callback' => __NAMESPACE__ . '\rest_api_permission_callback',
	]
);

/**
 * Return an error from the DKIM create key endpoint.
 *
 * @param string $msg The message to show.
 * @param bool   $ssl_failure Set to true to show OpenSSL errors.
 * @return \WP_REST_Response
 */
function dkim_create_error( $msg, $ssl_failure = false ) {
	$ssl_error = $ssl_failure ? get_openssl_errors() : '';

	return new \WP_REST_Response( [ 'error' => "{$msg}{$ssl_error}" ], 500 );
}

register_rest_route(
	EAUTH_API_PREFIX,
	sprintf( '/dkim/keys/(?P<name>%s)', EAUTH_DOMAIN_IN_URL_REGEX ),
	[
		'methods'             => 'POST',
		'callback'            => function ( \WP_REST_Request $request ) {
			$name = $request['name'];
			$obj  = $request->get_json_params();

			if ( ! $name ) {
				return dkim_create_error( 'No selector name given.' );
			}

			$keys = get_keys();

			if ( array_key_exists( $name, $keys ) ) {
				return dkim_create_error( 'A key with that name already exists.' );
			}

			$pk = array_key_exists( 'key', $obj )
				? openssl_pkey_get_private( $obj['key'] )
				: openssl_pkey_new(
					[
						'digest_alg'       => 'sha256',
						'private_key_bits' => 2048,
						'private_key_type' => OPENSSL_KEYTYPE_RSA,
					]
				);

			if ( ! $pk ) {
				return dkim_create_error( 'Failed to create private key.', true );
			}

			$exported = openssl_pkey_export( $pk, $private_string );

			if ( ! $exported ) {
				return dkim_create_error( 'Failed to export private key.', true );
			}

			$keys = array_merge(
				$keys,
				[
					$name => trim( $private_string ),
				]
			);

			save_keys( $keys );
		},
		'permission_callback' => __NAMESPACE__ . '\rest_api_permission_callback',
	]
);

register_rest_route(
	EAUTH_API_PREFIX,
	sprintf( '/dkim/keys/(?P<name>%s)/dns/(?P<domain>%s)', EAUTH_DOMAIN_IN_URL_REGEX, EAUTH_DOMAIN_IN_URL_REGEX ),
	[
		'methods'             => 'GET',
		'callback'            => function ( \WP_REST_Request $request ) {
			$name    = $request['name'];
			$domain  = $request['domain'];
			$keys    = get_keys();
			$pk_text = $keys[ $name ] ?? '';

			require_once __DIR__ . '/utils/check-dkim.php';
			return check_dkim_dns( $name, $domain, $pk_text );
		},
		'permission_callback' => __NAMESPACE__ . '\rest_api_permission_callback',
	]
);

register_rest_route(
	EAUTH_API_PREFIX,
	sprintf( '/dkim/keys/(?P<name>%s)/download', EAUTH_DOMAIN_IN_URL_REGEX ),
	[
		'methods'             => 'GET',
		'callback'            => function ( \WP_REST_Request $request ) {
			$name = $request['name'];
			$keys = get_keys();

			header( "Content-Disposition: attachment; filename=\"$name.pem\"" );
			header( 'Content-Type: application/x-pem-file' );

			// Output is not HTML, so escaping is not necessary.
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo $keys[ $name ];

			exit;
		},
		'permission_callback' => __NAMESPACE__ . '\rest_api_permission_callback',
	]
);

register_rest_route(
	EAUTH_API_PREFIX,
	sprintf( '/dkim/keys/(?P<name>%s)', EAUTH_DOMAIN_IN_URL_REGEX ),
	[
		'methods'             => 'DELETE',
		'callback'            => function ( \WP_REST_Request $request ) {
			$name = $request['name'];
			$keys = get_keys();

			unset( $keys[ $name ] );
			save_keys( $keys );
		},
		'permission_callback' => __NAMESPACE__ . '\rest_api_permission_callback',
	]
);

register_rest_route(
	EAUTH_API_PREFIX,
	sprintf( '/spf/check/(?P<domain>%s)', EAUTH_DOMAIN_IN_URL_REGEX ),
	[
		'methods'             => 'GET',
		'callback'            => function ( \WP_REST_Request $request ) {
			$domain = $request['domain'];
			$ip     = get_server_ip( $domain );

			require_once __DIR__ . '/utils/check-spf.php';
			return check_spf( $domain, $ip, get_domain() );
		},
		'permission_callback' => __NAMESPACE__ . '\rest_api_permission_callback',
	]
);

register_rest_route(
	EAUTH_API_PREFIX,
	'/spf/set-ip',
	[
		'methods'             => 'POST',
		'callback'            => function ( \WP_REST_Request $request ) {
			$obj = $request->get_json_params();

			update_option( 'eauth_spf_server_ip', $obj['mode'] );
			update_option( 'eauth_spf_server_ip_custom', $obj['custom'] );

			return [
				'mode'   => get_option( 'eauth_spf_server_ip' ),
				'custom' => get_option( 'eauth_spf_server_ip_custom' ),
			];
		},
		'permission_callback' => __NAMESPACE__ . '\rest_api_permission_callback',
	]
);

register_rest_route(
	EAUTH_API_PREFIX,
	sprintf( '/dmarc/check/(?P<domain>%s)', EAUTH_DOMAIN_IN_URL_REGEX ),
	[
		'methods'             => 'GET',
		'callback'            => function ( \WP_REST_Request $request ) {
			$domain = $request['domain'];

			require_once __DIR__ . '/utils/check-dmarc.php';
			return check_dmarc( $domain );
		},
		'permission_callback' => __NAMESPACE__ . '\rest_api_permission_callback',
	]
);

register_rest_route(
	EAUTH_API_PREFIX,
	sprintf( '/dmarc/org-domain/(?P<domain>%s)', EAUTH_DOMAIN_IN_URL_REGEX ),
	[
		'methods'             => 'GET',
		'callback'            => function ( \WP_REST_Request $request ) {
			$domain = $request['domain'];

			require_once __DIR__ . '/utils/fallback-domain.php';
			[ $org_domain, $org_domain_failure ] = call_user_func( $fallback_resolver ?? __NAMESPACE__ . '\fallback_domain', $domain );

			return [
				'org'  => $org_domain,
				'fail' => $org_domain_failure,
			];
		},
		'permission_callback' => __NAMESPACE__ . '\rest_api_permission_callback',
	]
);
