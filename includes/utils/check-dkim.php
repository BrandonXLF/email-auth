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
 * Create a DKIM failure result.
 *
 * @param string $reason The reason for the failure.
 * @param array  $warnings Warnings to include in the result.
 * @return array{ pass: bool, reason: string }
 */
function dkim_failure( $reason, &$warnings = [] ) {
	return [
		'pass'     => false,
		'reason'   => $reason,
		'warnings' => $warnings,
	];
}

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
 * @param string                  $pub The public key.
 * @param DNSTagValue\TxtResolver $txt_resolver DNS resolver for TXT records.
 * @return array{ pass: bool, reason: string|null }
 */
function check_dkim_dns( $name, $domain, $pub, $txt_resolver = null ) {
	require_once __DIR__ . '/dns-tag-value/dns-tag-value.php';
	require_once __DIR__ . '/dns-tag-value/class-txtresolver.php';

	$txt_resolver ??= new DNSTagValue\TxtResolver( get_net_dns2_resolver() );
	$host           = "$name._domainkey.$domain";
	$dkim           = null;
	$warnings       = [];

	if ( ! preg_match( EAUTH_DKIM_SELECTOR_REGEX, $name ) ) {
		$warnings[] = 'Selector name is non-standard.';
	}

	try {
		// Programs like Gmail seem to not filter records, so we perform checks on the first record instead.
		$dkim = DNSTagValue\get_map( $host, null, $warnings, $txt_resolver );
	} catch ( DNSTagValue\Exception $e ) {
		return dkim_failure( $e->getMessage(), $warnings );
	}

	if ( empty( $dkim['p'] ) ) {
		return dkim_failure( 'Public key is missing.', $warnings );
	}

	if ( $dkim['p'] !== $pub ) {
		return dkim_failure( 'Public key is incorrect.', $warnings );
	}

	if ( array_key_exists( 'v', $dkim ) ) {
		if ( array_key_first( $dkim ) !== 'v' ) {
			return dkim_failure( 'Version identifier must be the first tag if present.', $warnings );
		}

		if ( 'DKIM1' !== $dkim['v'] ) {
			return dkim_failure( 'Version identifier must be v=DKIM1 if present.', $warnings );
		}
	}

	if ( isset( $dkim['s'] ) && ! array_intersect( [ '*', 'email' ], parse_colon_list( $dkim['s'] ) ) ) {
		return dkim_failure( 'Record service type must include email (or *).', $warnings );
	}

	if ( isset( $dkim['t'] ) && in_array( 'y', parse_colon_list( $dkim['t'] ), true ) ) {
		$warnings[] = 'Test mode is enabled, DKIM policy might be ignored.';
	}

	return [
		'pass'     => $warnings ? 'partial' : true,
		'warnings' => $warnings,
	];
}
