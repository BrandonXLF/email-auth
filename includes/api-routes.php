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

/**
 * Check if the current user can use the admin API.
 *
 * @return bool
 */
function rest_api_permission_callback() {
	return current_user_can( 'manage_options' );
}


/**
 * Get all OpenSSL errors in a presentable.
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
	'/dkim/keys',
	[
		'methods'             => 'POST',
		'callback'            => function ( \WP_REST_Request $request ) {
			$obj  = $request->get_json_params();
			$name = $obj['name'];

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

/**
 * Return an OpenSSL error response for the DKIM check endpoint.
 *
 * @param string $host The DKIM DNS record host.
 * @param string $ctx The context for the OpenSSL error.
 * @return \WP_REST_Response
 */
function dkim_check_ssl_error( $host, $ctx ) {
	return new \WP_REST_Response(
		[
			'host'   => $host,
			'dns'    => null,
			'pass'   => false,
			'reason' => $ctx . get_openssl_errors( ' - ' ),
		],
		500
	);
}

register_rest_route(
	EAUTH_API_PREFIX,
	'/dkim/keys/(?P<name>[a-zA-Z0-9-]+)/dns/(?P<domain>[a-zA-Z0-9-.]+)',
	[
		'methods'             => 'GET',
		'callback'            => function ( \WP_REST_Request $request ) {
			$name   = $request['name'];
			$domain = $request['domain'];
			$host   = "$name._domainkey.$domain";

			$keys = get_keys();
			$key  = $keys[ $name ] ?? '';
			$pk   = openssl_pkey_get_private( $key );

			if ( ! $pk ) {
				return dkim_check_ssl_error( $host, 'Failed to read private key from store.' );
			}

			$pub = openssl_pkey_get_details( $pk );

			if ( ! $pub ) {
				return dkim_check_ssl_error( $host, 'Failed to get public key' );
			}

			$pub = $pub['key'];
			$pub = preg_replace( '/^-+.*?-+$/m', '', $pub );
			$pub = str_replace( [ "\r", "\n" ], '', $pub );
			$pub = trim( $pub );

			$dns = "v=DKIM1; h=sha256; t=s; p=$pub";

			require_once __DIR__ . '/utils/check-dkim.php';

			return array_merge(
				[
					'host' => $host,
					'dns'  => $dns,
				],
				check_dkim_dns( $host, $pub )
			);
		},
		'permission_callback' => __NAMESPACE__ . '\rest_api_permission_callback',
	]
);

register_rest_route(
	EAUTH_API_PREFIX,
	'/dkim/keys/(?P<name>[a-zA-Z0-9-]+)/download',
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
	'/dkim/keys/(?P<name>[a-zA-Z0-9-]+)',
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
	'/spf/check/(?P<domain>[a-zA-Z0-9-.]+)',
	[
		'methods'             => 'GET',
		'callback'            => function ( \WP_REST_Request $request ) {
			$domain = $request['domain'];
			$ip     = sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ?? '' ) );

			require_once __DIR__ . '/utils/check-spf.php';
			return check_spf( $domain, $ip, get_domain() );
		},
		'permission_callback' => __NAMESPACE__ . '\rest_api_permission_callback',
	]
);

register_rest_route(
	EAUTH_API_PREFIX,
	'/dmarc/check/(?P<domain>[a-zA-Z0-9-.]+)',
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
