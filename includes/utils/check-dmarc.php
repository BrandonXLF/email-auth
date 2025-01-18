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
 * @param array $record The DNS TXT record.
 * @return boolean True if the record is a valid DMARC DNS record.
 */
function is_dmarc_record( $record ) {
	return str_starts_with( trim( $record['txt'] ), 'v=DMARC1' );
}

/**
 * Transform the given exception to a failure return.
 *
 * @param DNSTagValue\Exception $e The exception.
 * @param string                $org The organizational domain.
 * @return array{ pass: bool, reason: string }
 */
function dmarc_failure( &$e, $org = null ) {
	return [
		'pass'     => false,
		'reason'   => $e->getMessage(),
		'warnings' => [],
		'infos'    => [],
		'org'      => $org,
	];
}

/**
 * Check DMARC for a given domain.
 *
 * @param string $domain The domain.
 * @param bool   $is_org True if the domain is a derived organizational domain.
 */
function check_dmarc( $domain, $is_org = false ) {
	require_once __DIR__ . '/dns-tag-value/dns-tag-value.php';

	/**
	 * Organizational domain if different from the base domain.
	 */
	$org_domain = null;

	if ( $is_org ) {
		$org_domain = $domain;
	} else {
		$org_domain_map = get_transient( 'eauth_org_domain_map' ) ?: [];
		$org_domain     = $org_domain_map[ $domain ] ?? null;

		if ( ! $org_domain ) {
			$file   = wp_remote_get( 'https://publicsuffix.org/list/public_suffix_list.dat' )['body'];
			$list   = \Pdp\Rules::fromString( $file );
			$result = $list->resolve( $domain );

			$org_domain = $result->registrableDomain()->toString();

			set_transient(
				'eauth_org_domain_map',
				[ $domain => $org_domain ],
				24 * HOUR_IN_SECONDS
			);
		}

		if ( $org_domain === $domain ) {
			$org_domain = null;
		}
	}

	$dmarc = null;

	try {
		$dmarc = DNSTagValue\get_map( "_dmarc.$domain", __NAMESPACE__ . '\is_dmarc_record' );
	} catch ( DNSTagValue\MissingException $e ) {
		if ( ! $org_domain || $org_domain === $domain ) {
			return dmarc_failure( $e, $org_domain );
		}

		return check_dmarc( $org_domain, true );
	} catch ( DNSTagValue\Exception $e ) {
		return dmarc_failure( $e, $org_domain );
	}

	$warnings = [];
	$infos    = [];
	$footnote = null;

	$policy = $is_org
		? ( $dmarc['sp'] ?? $dmarc['p'] ?? 'none' )
		: ( $dmarc['p'] ?? 'none' );

	if ( 'none' === $policy ) {
		$term_type  = isset( $dmarc['sp'] ) ? 'sp' : 'p';
		$warnings[] = "DMARC will pass regardless of DKIM and SPF alignment. Add a <code>$term_type=quarantine</code> or <code>$term_type=reject</code> term.";
	} elseif ( 'quarantine' === $policy ) {
		$infos[] = 'Failures will be treated as suspicious, but will not be outright rejected.';
	}

	if ( 'none' !== $policy ) {
		$footnote = 'DMARC only passes if at least one of <a href="#dkim">DKIM</a> and <a href="#spf">SPF</a> passes domain alignment.';
	}

	$pct = intval( $dmarc['pct'] ?? '100' );

	if ( $pct < 100 ) {
		$warnings[] = "DMARC will only fail for $pct% of failures.";
	}

	if ( ( $dmarc['adkim'] ?? 'r' ) === 'r' ) {
		$infos[] = 'DMARC will still pass if the DKIM domain and "From" domain share a common registered domain.';
	}

	if ( ( $dmarc['aspf'] ?? 'r' ) === 'r' ) {
		$infos[] = 'DMARC will still pass if the bounce domain and "From" domain share a common registered domain.';
	}

	return [
		'pass'     => $warnings ? 'partial' : true,
		'warnings' => $warnings,
		'infos'    => $infos,
		'footnote' => $footnote,
		'org'      => $org_domain,
	];
}
