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

/**
 * Check if the public key is set for a domain.
 *
 * @param string $domain The domain.
 * @param string $pub The public key.
 * @return array{ pass: bool, reason: string | null }
 */
function check_dkim_dns( $domain, $pub ) {
	require_once __DIR__ . '/dns-tag-value/dns-tag-value.php';
	$dkim = null;

	try {
		$dkim = DNSTagValue\get_map( $domain );
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

	return [ 'pass' => true ];
}
