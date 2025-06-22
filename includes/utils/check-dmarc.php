<?php
/**
 * Check if the given DNS TXT record matches a DMARC record.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Check if the given DNS TXT record matches a DMARC record.
 * Follows RFC 7489 6.6.3.
 *
 * @param array $tags  The list of tag-value pairs.
 * @return string|null Reason the record is not a DMARC record or null if it is.
 */
function is_dmarc_record( $tags ) {
	if ( ! array_key_exists( 'v', $tags ) ) {
		return 'Version identifier (v=DMARC1) is missing.';
	}

	if ( array_key_first( $tags ) !== 'v' ) {
		return 'First tag must be the version identifier (v).';
	}

	if ( 'DMARC1' !== $tags['v'] ) {
		return 'Version identifier must be v=DMARC1.';
	}

	return null;
}

/**
 * Internal, recursive function to check DMARC for a given domain.
 *
 * @access private
 *
 * @param string                       $domain The domain.
 * @param bool                         $is_org True if the domain is a derived organizational domain.
 * @param string|null                  $org_domain_failure Warnings from previous org domain retrieval.
 * @param DNSTagValue\TxtResolver|null $txt_resolver Function to get TXT records with.
 * @param callable|null                $fallback_resolver Function to resolve the fallback organizational domain.
 * @param array                        $base_warnings Existing warnings to append to.
 * @return array
 */
function _check_dmarc( $domain, $is_org, $org_domain_failure, $txt_resolver, $fallback_resolver, &$base_warnings = [] ) {
	require_once __DIR__ . '/dns-tag-value/dns-tag-value.php';
	require_once __DIR__ . '/dns-tag-value/class-txtresolver.php';

	$txt_resolver ??= new DNSTagValue\TxtResolver( get_net_dns2_resolver() );

	/**
	 * Organizational domain if different from the base domain.
	 */
	$org_domain = null;

	if ( $is_org ) {
		$org_domain = $domain;
	} else {
		require_once __DIR__ . '/fallback-domain.php';
		[ $org_domain, $org_domain_failure ] = call_user_func( $fallback_resolver ?? __NAMESPACE__ . '\fallback_domain', $domain );
	}

	$response = [
		'warnings' => $base_warnings,
		'infos'    => [],
		'org'      => $org_domain,
		'orgFail'  => $org_domain_failure,
		'relaxed'  => [],
	];

	$dmarc = null;

	try {
		[ $dmarc, $response['record'] ] = DNSTagValue\get_map( "_dmarc.$domain", __NAMESPACE__ . '\is_dmarc_record', $response['warnings'], $txt_resolver );
	} catch ( DNSTagValue\MissingException $e ) {
		if ( ! $org_domain || $org_domain === $domain ) {
			return api_failure( $e->getMessage(), $response );
		}

		return _check_dmarc( $org_domain, true, $org_domain_failure, $txt_resolver, $fallback_resolver, $response['warnings'] );
	} catch ( DNSTagValue\MalformedException $e ) {
		$response['record'] = $e->getRecordText();
		return api_failure( $e->getMessage(), $response );
	} catch ( DNSTagValue\Exception $e ) {
		return api_failure( $e->getMessage(), $response );
	}

	$policy = $is_org
		? ( $dmarc['sp'] ?? $dmarc['p'] ?? 'none' )
		: ( $dmarc['p'] ?? 'none' );

	if ( 'none' === $policy ) {
		$term_type              = isset( $dmarc['sp'] ) ? 'sp' : 'p';
		$response['warnings'][] = "DMARC will pass regardless of DKIM and SPF alignment. Add a <code>$term_type=quarantine</code> or <code>$term_type=reject</code> term.";
	} elseif ( 'quarantine' === $policy ) {
		$response['infos'][] = 'Failures will be treated as suspicious, but will not be outright rejected.';
	}

	$pct = intval( $dmarc['pct'] ?? '100' );

	if ( $pct < 100 ) {
		$response['warnings'][] = "DMARC will only fail for $pct% of failures.";
	}

	$response['relaxed']['dkim'] = ( $dmarc['adkim'] ?? 'r' ) === 'r';
	$response['infos'][]         = 'adkim: DKIM domain and "From" domain ' . ( $response['relaxed']['dkim'] ? 'need only share a common registered domain' : 'must be identical' ) . '.';

	$response['relaxed']['spf'] = ( $dmarc['aspf'] ?? 'r' ) === 'r';
	$response['infos'][]        = 'aspf: Bounce domain and "From" domain ' . ( $response['relaxed']['spf'] ? 'need only share a common registered domain' : 'must be identical' ) . '.';

	return api_pass( (bool) $response['warnings'], $response );
}

/**
 * Check DMARC for a given domain.
 *
 * @param string                  $domain The domain.
 * @param DNSTagValue\TxtResolver $txt_resolver DNS resolver for TXT records.
 * @param callable                $fallback_resolver Function to resolve the fallback organizational domain.
 * @return array
 */
function check_dmarc( $domain, $txt_resolver = null, $fallback_resolver = null ) {
	return _check_dmarc( $domain, false, null, $txt_resolver, $fallback_resolver );
}
