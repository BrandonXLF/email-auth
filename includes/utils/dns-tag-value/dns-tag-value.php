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
 * @param string      $domain The domain to get the DNS records from.
 * @param callable    $filter Function that filters out records with invalid tag-value pairs. If specified, malformed records are also ignored.
 *                         Returns HTML reason for filtering out the record, or null if the record is valid.
 * @param array       $filter_reasons Array to store reasons for filtering out records.
 * @param TxtResolver $txt_resolver Function to get TXT records with.
 * @return array[string]string The map of tag-value pairs.
 *
 * @throws InvalidException Too many records.
 * @throws MissingException Record could not be fetch or no record present.
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
					$filter_reasons[] = 'Potential record ignored: Malformed tag-value pair.';
					continue 2;
				}

				require_once __DIR__ . '/class-invalidexception.php';
				throw new InvalidException( 'Malformed tag-value pair.' );
			}

			$key = trim( substr( $part, 0, $pos ) );
			$val = trim( substr( $part, $pos + 1 ) );

			if ( array_key_exists( $key, $tags ) ) {
				require_once __DIR__ . '/class-invalidexception.php';
				throw new InvalidException( 'Multiple tag-values pairs with the same key (' . esc_html( $key ) . ').' );
			}

			$tags[ $key ] = $val;
		}

		if ( $filter ) {
			$filter_reason = call_user_func( $filter, $tags );

			if ( null !== $filter_reason ) {
				$filter_reasons[] = 'Potential record ignored: ' . $filter_reason;
				continue;
			}
		}

		if ( $valid_return ) {
			// Per RFC 6376 3.6.2.2 and RFC 7489 6.6.3.
			require_once __DIR__ . '/class-invalidexception.php';
			throw new InvalidException( 'Multiple TXT records found, only one should be present.' );
		}

		$valid_return = $tags;
	}

	unset( $record );

	if ( ! $valid_return ) {
		require_once __DIR__ . '/class-missingexception.php';
		throw new MissingException( 'No TXT record found.' );
	}

	return $valid_return;
}
