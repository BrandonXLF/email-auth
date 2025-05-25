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
 * Get a DNS record, turning warnings raised by dns_get_record into exceptions.
 *
 * @param string $domain The hostname to query.
 * @param int    $type The type of record to fetch.
 * @return array
 *
 * @throws MissingException Record could not be fetched.
 */
function get_record_throws( $domain, $type = DNS_ANY ) {
	// phpcs:disable Generic.CodeAnalysis.EmptyStatement.DetectedCatch
	try {
		$domain = \MLocati\IDNA\DomainName::fromName( $domain )->getPunycode();
	} catch ( \MLocati\IDNA\Exception\Exception $_ ) {
		// Keep domain name as is.
	}
	// phpcs:enable

	// Not for debugging.
	// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler
	set_error_handler(
		function ( $_, $msg ) use ( &$error ) {
			require_once __DIR__ . '/class-missingexception.php';
			$error = new MissingException( 'Could not retrieve DNS record. ' . $msg );
			return true;
		},
		E_WARNING
	);

	$res = dns_get_record( $domain, $type );

	restore_error_handler();

	if ( isset( $error ) ) {
		throw $error;
	}

	if ( false === $res ) {
		require_once __DIR__ . '/class-missingexception.php';
		throw new MissingException( 'Could not retrieve DNS record.' );
	}

	return $res;
}

/** Default function for retrieving DNS TXT records.
 *
 * @param string $domain The hostname to query.
 * @return array
 *
 * @throws MissingException Record could not be fetched.
 */
function get_txt_record( $domain ) {
	return get_record_throws( $domain, DNS_TXT );
}

/**
 * Get the DNS tag-value map for a given domain for DKIM and DMARC.
 *
 * @param string   $domain The domain to get the DNS records from.
 * @param callable $filter Function that filters out records with invalid tag-value pairs.
 * 	                       If specified, malformed records are also ignored.
 * @param array    $filter_reasons Array to store reasons for filtering out records.
 * @param callable $txt_resolver Function to get TXT records with.
 * @return array[string]string The map of tag-value pairs.
 *
 * @throws InvalidException Too many records.
 * @throws MissingException Record could not be fetch or no record present.
 */
function get_map( $domain, $filter = null, &$filter_reasons = [], $txt_resolver = null ) {
	$records = call_user_func( $txt_resolver ?? __NAMESPACE__ . '\get_txt_record', $domain );

	foreach ( $records as &$record ) {
		if ( isset( $record['entries'] ) ) {
			$record['txt'] = implode( '', $record['entries'] );
		}
	}

	unset( $record );

	$valid_return = null;

	foreach ( $records as &$record ) {
		$parts  = explode( ';', trim( $record['txt'] ) );
		
		$last = array_pop( $parts );
		if ( $last !== '') {
			array_push( $parts, $last );
		}

		$tags   = [];

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
				throw new InvalidException( 'Multiple tag-values pairs with the same key (' . $key . ').' );
			}

			$tags[ $key ] = $val;
		}

		if ( $filter ) {
			$filter_reason = call_user_func( $filter, $tags );

			if ( $filter_reason !== null ) {
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
		throw new MissingException('No TXT record found.' );
	}

	return $valid_return;
}
