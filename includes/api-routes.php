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

register_rest_route(
	EAUTH_API_PREFIX,
	'/dkim/keys',
	[
		'methods'             => 'POST',
		'callback'            => function ( \WP_REST_Request $request ) {
			$obj = $request->get_json_params();

			$name = $obj['name'];
			$pk;

			if ( ! $name ) {
				http_response_code( 500 );
				return 'No name given via body.';
			}

			if ( array_key_exists( 'key', $obj ) ) {
				$pk = openssl_pkey_get_private( $obj['key'] );
			} else {
				$pk = openssl_pkey_new(
					[
						'digest_alg'       => 'sha256',
						'private_key_bits' => 2048,
						'private_key_type' => OPENSSL_KEYTYPE_RSA,
					]
				);
			}

			if ( ! $pk ) {
				http_response_code( 500 );
				return 'Failed to create private key.';
			}

			openssl_pkey_export( $pk, $private_string );

			$keys = array_merge(
				get_keys(),
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
	'/dkim/keys/(?P<name>[a-zA-Z0-9-]+)/dns/(?P<domain>[a-zA-Z0-9-.]+)',
	[
		'methods'             => 'GET',
		'callback'            => function ( \WP_REST_Request $request ) {
			$name   = $request['name'];
			$domain = $request['domain'];
			$host   = "$name._domainkey.$domain";

			$keys = get_keys();
			$key  = $keys[ $name ];
			$pk   = openssl_pkey_get_private( $key );

			$pub = openssl_pkey_get_details( $pk )['key'];
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

			// Output is not HTML, so escaping is not nessessary.
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
			$domain     = $request['domain'];
			$record     = ( new \SPFLib\Decoder() )->getRecordFromDomain( $domain );
			$has_issues = false;
			$comments   = [];

			if ( $record ) {
				$validator = new \SPFLib\OnlineSemanticValidator();

				$comments = $validator->validateRecord( $record );
				$comments = array_map(
					function ( &$issue ) use ( &$has_issues ) {
						if ( $issue->getLevel() === \SPFLib\Issue::LEVEL_FATAL ) {
								$has_issues = true;

								return [
									'level' => 'error',
									'desc'  => $issue->getDescription(),
								];
						}

						if ( $issue->getLevel() === \SPFLib\Issue::LEVEL_WARNING ) {
							$has_issues = true;

							return [
								'level' => 'warning',
								'desc'  => $issue->getDescription(),
							];
						}

						return [
							'desc' => $issue->getDescription(),
						];
					},
					$comments
				);
			}

			// SERVER_ADDR is populated by the server.
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$ip = wp_unslash( $_SERVER['SERVER_ADDR'] ?? '' );

			$environment  = new \SPFLib\Check\Environment( $ip, '', "test@$domain" );
			$checker      = new \SPFLib\Checker();
			$check_result = $checker->check( $environment );
			$code         = $check_result->getCode();
			$rec_reasons  = [];

			if ( 'none' === $code ) {
				$has_issues = true;

				$comments[] = [
					'level' => 'error',
					'desc'  => 'Could not retrive DNS records.',
				];
			}

			if ( $record ) {
				$terms = $record->getTerms();

				if ( 'fail' === $code || 'softfail' === $code || 'neutral' === $code ) {
					$new_record = new \SPFLib\Term\Mechanism\AMechanism( \SPFLib\Term\Mechanism::QUALIFIER_PASS, get_domain() );

					$record->clearTerms();

					foreach ( $terms as &$term ) {
						if ( $new_record && ( $term instanceof \SPFLib\Term\Mechanism\AllMechanism ) ) {
							$record->addTerm( $new_record );
							$new_record = null;
						}

						$record->addTerm( $term );
					}

					if ( $new_record ) {
						$record->addTerm( $new_record );
					}

					$rec_reasons[] = [
						'level' => 'error',
						'desc'  => 'Website host is not included in a pass case of the SPF record.',
					];
				}

				$has_all = false;

				foreach ( $terms as &$term ) {
					if ( $term instanceof \SPFLib\Term\Mechanism\AllMechanism ) {
						$has_all = true;
						break;
					}
				}

				if ( ! $has_all ) {
					$record->addTerm( new \SPFLib\Term\Mechanism\AllMechanism( \SPFLib\Term\Mechanism::QUALIFIER_SOFTFAIL ) );

					$rec_reasons[] = [
						'level' => 'warning',
						'desc'  => 'An <code>~all</code> or <code>-all</code> term is recommended to (soft) fail all other servers.',
					];
				}
			}

			return [
				'pass'        => 'pass' === $code ? ( $has_issues || $rec_reasons ? 'partial' : true ) : false,
				'reason'      => 'pass' !== $code ? 'SPF check did not pass.' : null,
				'code'        => $code,
				'comments'    => $comments,
				'rec_dns'     => count( $rec_reasons ) ? strval( $record ) : null,
				'rec_reasons' => $rec_reasons,
			];
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
