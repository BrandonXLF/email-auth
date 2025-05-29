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
 * @param string         $qualifier      The qualifier to use for the new "all" term.
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
	require_once __DIR__ . '/spf/class-dnsresolver.php';

	$dns_resolver ??= new SPF\DNSResolver( get_net_dns2_resolver() );
	$environment    = new \SPFLib\Check\Environment( $ip, '', "test@$domain" );
	$checker        = new \SPFLib\Checker( $dns_resolver );
	$check_result   = $checker->check( $environment );
	$code           = $check_result->getCode();
	$full_non_pass  = 'fail' === $code || 'softfail' === $code || 'neutral' === $code;

	$code_reasons = array_map(
		function ( $msg ) {
			return [
				'level' => 'error',
				'desc'  => esc_html( $msg ),
			];
		},
		$check_result->getMessages()
	);

	if ( $full_non_pass && $check_result->getMatchedMechanism() ) {
		$code_reasons[] = [
			'desc' => 'Non-pass caused by: <code>' . esc_html( $check_result->getMatchedMechanism() ) . '</code>',
		];
	}

	$decoder = new \SPFLib\Decoder( $dns_resolver );

	try {
		$record = $decoder->getRecordFromDomain( $domain );
	} catch ( \Exception $e ) {
		$record = null;
	}

	$validity    = [];
	$invalid     = false;
	$rec_reasons = [];

	if ( $record ) {
		$validator = new \SPFLib\OnlineSemanticValidator( $decoder );
		$validity  = array_merge(
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

		$terms = $record->getTerms();

		if ( $full_non_pass ) {
			$rec_record = new \SPFLib\Record();
			$new_term   = new \SPFLib\Term\Mechanism\AMechanism( \SPFLib\Term\Mechanism::QUALIFIER_PASS, $server_domain );

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

			$rec_reasons[] = [
				'level' => 'error',
				'desc'  => 'Website host (' . $domain . ' or ' . esc_html( $ip ) . ') is not included in a pass case of the SPF record.',
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
		'cur_rec'      => $record ? (string) $record : null,
		'cur_validity' => $validity,
		'rec_dns'      => count( $rec_reasons ) ? (string) $rec_record : null,
		'rec_reasons'  => $rec_reasons,
		'server_ip'    => $ip,
	];
}
