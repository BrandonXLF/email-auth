<?php
/**
 * Check if the public key is set for a domain.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Per RFC 6367 3.1 and RFC 5321 4.1.2.
define(
	'EAUTH_DKIM_SELECTOR_REGEX',
	'/^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/'
);

/**
 * Parse a colon-separated list of strings.
 *
 * @param string $str The string to parse.
 * @return array The parsed list of strings.
 */
function parse_colon_list( $str ) {
	$parts = explode( ':', $str );
	$parts = array_map( 'trim', $parts );
	return $parts;
}

/**
 * Check if the public key is set for a domain.
 *
 * @param string                  $name The DKIM selector.
 * @param string                  $domain The base domain.
 * @param string                  $pk_text The private key.
 * @param DNSTagValue\TxtResolver $txt_resolver DNS resolver for TXT records.
 * @return array{ pass: bool, reason: string|null }
 */
function check_dkim_dns( $name, $domain, $pk_text, $txt_resolver = null ) {
	$host = "$name._domainkey.$domain";
	$pk   = openssl_pkey_get_private( $pk_text );

	$response = [
		'host'     => $host,
		'warnings' => [], // Note: Array of HTML strings.
	];

	if ( ! $pk ) {
		return api_failure( 'Failed to read private key from store.' . get_openssl_errors( ' - ' ), $response );
	}

	$pub = openssl_pkey_get_details( $pk );

	if ( ! $pub ) {
		return api_failure( 'Failed to get public key.' . get_openssl_errors( ' - ' ), $response );
	}

	$pub = $pub['key'];
	$pub = preg_replace( '/^-+.*?-+$/m', '', $pub );
	$pub = str_replace( [ "\r", "\n" ], '', $pub );
	$pub = trim( $pub );

	$response['dns'] = "v=DKIM1; h=sha256; t=s; p=$pub";

	require_once __DIR__ . '/dns-tag-value/dns-tag-value.php';
	require_once __DIR__ . '/dns-tag-value/class-txtresolver.php';

	$txt_resolver ??= new DNSTagValue\TxtResolver( get_net_dns2_resolver() );
	$dkim           = null;

	if ( ! preg_match( EAUTH_DKIM_SELECTOR_REGEX, $name ) ) {
		$response['warnings'][] = 'Selector name is non-standard.';
	}

	try {
		// Programs like Gmail seem to not filter records, so we perform checks on the first record instead.
		[ $dkim, $response['record'] ] = DNSTagValue\get_map( $host, null, $response['warnings'], $txt_resolver );
	} catch ( DNSTagValue\MalformedException $e ) {
		$response['record'] = $e->getRecordText();
		return api_failure( $e->getMessage(), $response );
	} catch ( DNSTagValue\Exception $e ) {
		return api_failure( $e->getMessage(), $response );
	}

	if ( empty( $dkim['p'] ) ) {
		return api_failure( 'Public key is missing.', $response );
	}

	if ( $dkim['p'] !== $pub ) {
		return api_failure( 'Public key is incorrect.', $response );
	}

	if ( array_key_exists( 'v', $dkim ) ) {
		if ( array_key_first( $dkim ) !== 'v' ) {
			return api_failure( 'Version identifier must be the first tag if present.', $response );
		}

		if ( 'DKIM1' !== $dkim['v'] ) {
			return api_failure( 'Version identifier must be v=DKIM1 if present.', $response );
		}
	}

	if ( isset( $dkim['s'] ) && ! array_intersect( [ '*', 'email' ], parse_colon_list( $dkim['s'] ) ) ) {
		return api_failure( 'Record service type must include email (or *).', $response );
	}

	if ( isset( $dkim['t'] ) && in_array( 'y', parse_colon_list( $dkim['t'] ), true ) ) {
		$response['warnings'][] = 'Test mode is enabled, DKIM policy might be ignored.';
	}

	return api_pass( (bool) $response['warnings'], $response );
}
