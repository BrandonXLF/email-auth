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
 * @throws MissingException Record could not be fetch.
 */
function get_record_throws( $domain, $type = DNS_ANY ) {
	// Not for debugging.
	// phpcs:disable WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler
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

/**
 * Get the DNS tag-value map for a given domain for DKIM and DMARC.
 *
 * @param string   $domain The domain to get the DNS records from.
 * @param callable $filter The function to use to filter DNS TXT records.
 * @return array[string]string The map of tag-value pairs.
 *
 * @throws InvalidException Too many records.
 * @throws MissingException Record could not be fetch or no record present.
 */
function get_map( $domain, $filter = '__return_true' ) {
	// Error will be thrown by DNS retrieval below.
	// phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged
	$cname = @dns_get_record( $domain, DNS_CNAME );

	if ( $cname && count( $cname ) ) {
		return get_map( $cname[0]['target'], $filter );
	}

	$records = get_record_throws( $domain, DNS_TXT );
	$records = array_filter( $records, $filter );

	if ( count( $records ) > 1 ) {
		// Per RFC 6376 3.6.2.2 and RFC 7489 6.6.3.
		require_once __DIR__ . '/class-invalidexception.php';
		throw new InvalidException( 'Multiple TXT records found, only one should be present.' );
	}

	if ( empty( $records ) ) {
		require_once __DIR__ . '/class-missingexception.php';
		throw new MissingException( 'No TXT record found.' );
	}

	$record = $records[0];

	if ( isset( $record['entries'] ) ) {
		$record['txt'] = implode( '', $record['entries'] );
	}

	$parts = array_filter( explode( ';', trim( $record['txt'] ) ) );
	$tags  = [];

	foreach ( $parts as $part ) {
		list( $key, $val ) = explode( '=', trim( $part ), 2 );
		$tags[ $key ]      = $val;
	}

	return $tags;
}
