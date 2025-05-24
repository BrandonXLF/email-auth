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
 * Check if the public key is set for a domain.
 *
 * @param string   $name The DKIM selector.
 * @param string   $domain The base domain.
 * @param string   $pub The public key.
 * @param callable $txt_resolver Function to get TXT records with.
 * @return array{ pass: bool, reason: string | null }
 */
function check_dkim_dns( $name, $domain, $pub, $txt_resolver = null ) {
	require_once __DIR__ . '/dns-tag-value/dns-tag-value.php';

	$host = "$name._domainkey.$domain";
	$dkim = null;

	try {
		$dkim = DNSTagValue\get_map( $host, null, $txt_resolver );
	} catch ( DNSTagValue\Exception $e ) {
		return [
			'pass'   => false,
			'reason' => $e->getMessage(),
		];
	}

	if ( empty( $dkim['p'] ) ) {
		return [
			'pass'   => false,
			'reason' => 'Public key is missing.',
		];
	}

	if ( $dkim['p'] !== $pub ) {
		return [
			'pass'   => false,
			'reason' => 'Public key is incorrect.',
		];
	}

	if ( ! preg_match( EAUTH_DKIM_SELECTOR_REGEX, $name ) ) {
		return [
			'pass'   => 'partial',
			'reason' => 'Selector name is non-standard.',
		];
	}

	return [ 'pass' => true ];
}
