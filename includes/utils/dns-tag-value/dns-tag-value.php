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
 * @param sring    $domain The domain to get the DNS records from.
 * @param callable $filter The function to use to filter DNS TXT records.
 * @return array[string]string The map of tag-value pairs.
 *
 * @throws InvalidException Record could not be fetch or too many records.
 * @throws MissingException No record found.
 */
function get_map( $domain, $filter = '__return_true' ) {
	$cname = dns_get_record( $domain, DNS_CNAME );

	if ( count( $cname ) ) {
		return get_map( $cname[0]['target'], $filter );
	}

	$records = dns_get_record( $domain, DNS_TXT );
	$records = array_filter( $records, $filter );

	if ( false === $records ) {
		require_once __DIR__ . '/class-invalidexception.php';
		throw new InvalidException( 'Could not get DNS record.' );
	}

	if ( count( $records ) > 1 ) {
		// Per RFC 6375 3.6.2.2 and RFC 7489 6.6.3.
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
