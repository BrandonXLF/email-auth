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
			$domain               = $request['domain'];
			$ip                   = sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ?? '' ) );
			$environment          = new \SPFLib\Check\Environment( $ip, '', "test@$domain" );
			$checker              = new \SPFLib\Checker();
			$check_result         = $checker->check( $environment );
			$code                 = $check_result->getCode();
			$intentional_non_pass = 'fail' === $code || 'softfail' === $code || 'neutral' === $code;

			$code_reasons = array_map(
				function ( $msg ) {
					return [
						'level' => 'error',
						'desc'  => $msg,
					];
				},
				$check_result->getMessages()
			);

			if ( $intentional_non_pass && $check_result->getMatchedMechanism() ) {
				$code_reasons[] = [
					'level' => 'error',
					'desc'  => 'Non-pass caused by: <code>' . $check_result->getMatchedMechanism() . '</code>',
				];
			}

			try {
				$record = ( new \SPFLib\Decoder() )->getRecordFromDomain( $domain );
			} catch ( \Exception $e ) {
				$record = null;
			}

			$validity    = [];
			$invalid     = false;
			$rec_reasons = [];

			if ( $record ) {
				$validator = new \SPFLib\OnlineSemanticValidator();
				$validity  = array_merge(
					array_map(
						function ( $issue ) use ( &$invalid ) {
							if ( $issue->getLevel() === \SPFLib\Semantic\Issue::LEVEL_FATAL ) {
								$invalid = true;

								return [
									'level' => 'error',
									'desc'  => $issue->getDescription(),
								];
							}

							if ( $issue->getLevel() === \SPFLib\Semantic\Issue::LEVEL_WARNING ) {
								$invalid = true;

								return [
									'level' => 'warning',
									'desc'  => $issue->getDescription(),
								];
							}

							return [
								'desc' => $issue->getDescription(),
							];
						},
						$validator->validateRecord( $record )
					)
				);

				$terms = $record->getTerms();

				if ( $intentional_non_pass ) {
					$rec_record = new \SPFLib\Record();
					$new_term   = new \SPFLib\Term\Mechanism\AMechanism( \SPFLib\Term\Mechanism::QUALIFIER_PASS, get_domain() );

					foreach ( $terms as &$term ) {
						if ( $new_term && ( $term instanceof \SPFLib\Term\Mechanism\AllMechanism ) ) {
							$rec_record->addTerm( $new_term );
							$new_term = null;
						}

						$rec_record->addTerm( $term );
					}

					if ( $new_term ) {
						$rec_record->addTerm( $new_term );
					}

					$rec_reasons[] = [
						'level' => 'error',
						'desc'  => 'Website host is not included in a pass case of the SPF record.',
					];
				} else {
					$rec_record = clone $record;
				}

				$has_all = false;

				foreach ( $terms as &$term ) {
					if ( $term instanceof \SPFLib\Term\Mechanism\AllMechanism ) {
						$has_all = true;
						break;
					}
				}

				if ( ! $has_all ) {
					$rec_record->addTerm( new \SPFLib\Term\Mechanism\AllMechanism( \SPFLib\Term\Mechanism::QUALIFIER_SOFTFAIL ) );

					$rec_reasons[] = [
						'level' => 'warning',
						'desc'  => 'An <code>~all</code> or <code>-all</code> term is recommended to (soft) fail all other servers.',
					];
				}
			}

			return [
				'pass'         => 'pass' === $code ? ( $invalid || $rec_reasons ? 'partial' : true ) : false,
				'reason'       => 'pass' !== $code ? 'SPF check did not pass.' : null,
				'code'         => $code,
				'code_reasons' => $code_reasons,
				'cur_rec'      => (string) $record,
				'cur_validity' => $validity,
				'rec_dns'      => count( $rec_reasons ) ? (string) $rec_record : null,
				'rec_reasons'  => $rec_reasons,
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
