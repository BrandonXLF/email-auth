<?php
/**
 * Check the SPF record for a domain.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

/**
 * Remove any "all" terms and replace them with new "all" term.
 *
 * @param \SPFLib\Record $record The SPF record to modify.
 * @param string         $qualifier The qualifier to use for the new "all" term.
 * @return void
 */
function replace_spf_all_term( \SPFLib\Record &$record, string $qualifier ) {
	$terms = $record->getTerms();
	$record->clearTerms();

	foreach ( $terms as $t ) {
		if ( ! ( $t instanceof \SPFLib\Term\Mechanism\AllMechanism ) ) {
			$record->addTerm( $t );
		}
	}

	$record->addTerm( new \SPFLib\Term\Mechanism\AllMechanism( $qualifier ) );
}

/**
 * Check the SPF record for a domain.
 *
 * @param string               $domain The domain to check.
 * @param string               $ip The IP of the sending server.
 * @param string               $server_domain The domain of the sending server.
 * @param \SPFLib\DNS\Resolver $dns_resolver The DNS resolver.
 * @return array
 */
function check_spf( $domain, $ip, $server_domain, $dns_resolver = null ) {
	$response = [
		'code_reasons' => [], // Note: Array contains HTML string desc's.
		'server_ip'    => $ip,
		'validity'     => false, // Note: Array contains HTML string desc's (or false).
	];

	require_once __DIR__ . '/spf/class-dnsresolver.php';
	$dns_resolver ??= new SPF\DNSResolver( get_net_dns2_resolver() );

	try {
		$environment = new \SPFLib\Check\Environment( $ip, '', "test@$domain" );
	} catch ( \SPFLib\Exception\InvalidIPAddressException $e ) {
		$response['code_reasons'][] = [
			'level' => 'error',
			'desc'  => 'Configured IP address (' . esc_html( $ip ) . ') is invalid. Using <code>0.0.0.0</code>.',
		];

		$ip          = '0.0.0.0';
		$environment = new \SPFLib\Check\Environment( $ip, '', "test@$domain" );
	}

	$checker       = new \SPFLib\Checker( $dns_resolver );
	$check_result  = $checker->check( $environment );
	$code          = $check_result->getCode();
	$full_non_pass = 'fail' === $code || 'softfail' === $code || 'neutral' === $code;

	$response['code']         = $code;
	$response['code_reasons'] = array_merge(
		$response['code_reasons'],
		array_map(
			function ( $msg ) {
				return [
					'level' => 'error',
					'desc'  => esc_html( $msg ),
				];
			},
			$check_result->getMessages()
		)
	);

	if ( $full_non_pass && $check_result->getMatchedMechanism() ) {
		$response['code_reasons'][] = [
			'desc' => 'Non-pass caused by: <code>' . esc_html( $check_result->getMatchedMechanism() ) . '</code>',
		];
	}

	$decoder = new \SPFLib\Decoder( $dns_resolver );

	try {
		$record_txt = $decoder->getTXTRecordFromDomain( $domain );
	} catch ( \Exception $e ) {
		return api_failure( 'Could not fetch SPF record.', $response );
	}

	$response['record'] = $record_txt;

	try {
		$record = $decoder->getRecordFromTXT( $record_txt );
	} catch ( \Exception $e ) {
		return api_failure( 'Could not decode SPF record.', $response );
	}

	if ( ! $record ) {
		return api_failure( 'No SPF record found.', $response );
	}

	$invalid              = false;
	$validator            = new \SPFLib\OnlineSemanticValidator( $decoder );
	$response['validity'] = array_merge(
		array_map(
			function ( $issue ) use ( &$invalid ) {
				if ( $issue->getLevel() === \SPFLib\Semantic\Issue::LEVEL_FATAL ) {
					$invalid = true;

					return [
						'level' => 'error',
						'desc'  => esc_html( $issue->getDescription() ),
					];
				}

				if ( $issue->getLevel() === \SPFLib\Semantic\Issue::LEVEL_WARNING ) {
					$invalid = true;

					return [
						'level' => 'warning',
						'desc'  => esc_html( $issue->getDescription() ),
					];
				}

				return [
					'desc' => esc_html( $issue->getDescription() ),
				];
			},
			$validator->validateRecord( $record )
		)
	);

	$terms                   = $record->getTerms();
	$response['rec_reasons'] = []; // Note: Array of HTML strings.

	$only_matched_by_all = $check_result->getMatchedMechanism() instanceof \SPFLib\Term\Mechanism\AllMechanism;
	if ( $only_matched_by_all ) {
		// Check if all terms are "all" mechanisms. Won't return false positives, but doesn't catch more complex cases.
		foreach ( $terms as $term ) {
			if ( ! ( $term instanceof \SPFLib\Term\Mechanism\AllMechanism ) ) {
				$only_matched_by_all = false;
				break;
			}
		}
	}

	if ( $full_non_pass || $only_matched_by_all ) {
		$rec_record = new \SPFLib\Record();
		$new_term   = filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 )
			? new \SPFLib\Term\Mechanism\Ip6Mechanism( \SPFLib\Term\Mechanism::QUALIFIER_PASS, \IPLib\Address\IPv6::parseString( $ip ) )
			: new \SPFLib\Term\Mechanism\Ip4Mechanism( \SPFLib\Term\Mechanism::QUALIFIER_PASS, \IPLib\Address\IPv4::parseString( $ip ) );

		foreach ( $terms as &$term ) {
			if ( $new_term && ( $term instanceof \SPFLib\Term\Mechanism\AllMechanism ) ) {
				$rec_record->addTerm( $new_term );
				$new_term = null;
			}

			$rec_record->addTerm( $term );
		}

		unset( $term );

		if ( $new_term ) {
			$rec_record->addTerm( $new_term );
		}

		$response['rec_reasons'][] = [
			'level' => $full_non_pass ? 'error' : 'warning',
			'desc'  => $full_non_pass
				? 'Server (' . esc_html( $ip ) . ' or ' . esc_html( $server_domain ) . ') is not included in a pass case of the SPF record.'
				: 'Server (' . esc_html( $ip ) . ' or ' . esc_html( $server_domain ) . ') is only matched by an <code>all</code> term in the SPF record.',
		];
	} else {
		$rec_record = clone $record;
	}

	$all_term = null;

	foreach ( $terms as &$term ) {
		if ( $term instanceof \SPFLib\Term\Mechanism\AllMechanism ) {
			$all_term = $term;
			break;
		}
	}

	if ( ! $all_term || ( $all_term->getQualifier() !== \SPFLib\Term\Mechanism::QUALIFIER_SOFTFAIL && $all_term->getQualifier() !== \SPFLib\Term\Mechanism::QUALIFIER_FAIL ) ) {
		replace_spf_all_term( $rec_record, \SPFLib\Term\Mechanism::QUALIFIER_SOFTFAIL );

		$response['rec_reasons'][] = [
			'level' => 'warning',
			'desc'  => 'An <code>~all</code> or <code>-all</code> term is recommended to (soft) fail all other servers.',
		];
	}

	$response['rec_dns'] = count( $response['rec_reasons'] ) ? (string) $rec_record : null;

	return api_response(
		'pass' === $code ? ( $invalid || $response['rec_reasons'] ? 'partial' : true ) : false,
		'pass' !== $code ? 'SPF check did not pass.' : null,
		$response
	);
}
