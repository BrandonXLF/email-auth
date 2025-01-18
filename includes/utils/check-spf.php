<?php
/**
 * Check the SPF record for a domain.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

/**
 * Check the SPF record for a domain.
 *
 * @param string $domain The domain.
 * @param string $ip The IP of the sending server.
 * @return array
 */
function check_spf( $domain, $ip ) {
	$environment   = new \SPFLib\Check\Environment( $ip, '', "test@$domain" );
	$checker       = new \SPFLib\Checker();
	$check_result  = $checker->check( $environment );
	$code          = $check_result->getCode();
	$full_non_pass = 'fail' === $code || 'softfail' === $code || 'neutral' === $code;

	$code_reasons = array_map(
		function ( $msg ) {
			return [
				'level' => 'error',
				'desc'  => $msg,
			];
		},
		$check_result->getMessages()
	);

	if ( $full_non_pass && $check_result->getMatchedMechanism() ) {
		$code_reasons[] = [
			'desc' => 'Non-pass caused by: <code>' . $check_result->getMatchedMechanism() . '</code>',
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

		if ( $full_non_pass ) {
			$rec_record = new \SPFLib\Record();
			$new_term   = new \SPFLib\Term\Mechanism\AMechanism( \SPFLib\Term\Mechanism::QUALIFIER_PASS, get_domain() );

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
}
