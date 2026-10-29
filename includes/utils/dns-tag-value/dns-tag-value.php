<?php
/**
 * Get the DNS tag-value map for a given domain.
 *
 * @package Email Auth
 * @subpackage DNS Tag-Value
 */

namespace EmailAuthPlugin\DNSTagValue;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Get the DNS tag-value map for a given domain for DKIM and DMARC.
 *
 * @param string                                   $domain         The domain to get the DNS records from.
 * @param callable(array<string, string>): ?string $filter         Optional record validator; returns an HTML reason or null if valid.
 * @param array<int, string>                       $filter_reasons Reasons for filtered records (by reference).
 * @param TxtResolver|null                         $txt_resolver   DNS TXT resolver.
 * @return array{array<string, string>, string}                     Tag map and raw TXT record text.
 *
 * @throws MissingException Record could not be fetch or no record present.
 * @throws InvalidException DNS retrieval returned results, but the result are invalid. Eg: Multiple DNS records.
 * @throws MalformedException Record is malformed.
 */
function get_map( $domain, $filter = null, &$filter_reasons = [], $txt_resolver = null ) {
	require_once __DIR__ . '/class-txtresolver.php';

	$txt_resolver ??= new TxtResolver();
	$records        = $txt_resolver->get_records( $domain );
	$valid_return   = null;

	foreach ( $records as &$record ) {
		$parts = explode( ';', trim( $record ) );

		$last = array_pop( $parts );
		if ( '' !== $last ) {
			array_push( $parts, $last );
		}

		$tags = [];

		foreach ( $parts as $part ) {
			$part = trim( $part );
			$pos  = strpos( $part, '=' );

			if ( false === $pos ) {
				if ( $filter ) {
					$filter_reasons[] = \__( 'Potential record ignored: Malformed tag-value pair.', 'email-auth' );
					continue 2;
				}

				require_once __DIR__ . '/class-malformedexception.php';
				throw new MalformedException( \__( 'Malformed tag-value pair.', 'email-auth' ), $record );
			}

			$key = trim( substr( $part, 0, $pos ) );
			$val = trim( substr( $part, $pos + 1 ) );

			if ( array_key_exists( $key, $tags ) ) {
				require_once __DIR__ . '/class-malformedexception.php';
				throw new MalformedException(
					sprintf(
						/* translators: %s: duplicate DNS tag key */
						\__( 'Multiple tag-values pairs with the same key (%s).', 'email-auth' ),
						$key
					),
					$record
				);
			}

			$tags[ $key ] = $val;
		}

		if ( $filter ) {
			$filter_reason = call_user_func( $filter, $tags );

			if ( null !== $filter_reason ) {
				$filter_reasons[] = sprintf(
					/* translators: %s: reason the DNS record was ignored */
					\__( 'Potential record ignored: %s', 'email-auth' ),
					$filter_reason
				);
				continue;
			}
		}

		if ( $valid_return ) {
			// Per RFC 6376 3.6.2.2 and RFC 7489 6.6.3.
			require_once __DIR__ . '/class-invalidexception.php';
			throw new InvalidException( \__( 'Multiple TXT records found, only one should be present.', 'email-auth' ) );
		}

		$valid_return = [ $tags, $record ];
	}

	unset( $record );

	if ( ! $valid_return ) {
		require_once __DIR__ . '/class-missingexception.php';
		throw new MissingException( \__( 'No TXT record found.', 'email-auth' ) );
	}

	return $valid_return;
}
