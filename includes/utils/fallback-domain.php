<?php
/**
 * Get the fallback organizational domain of a domain.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

/**
 * Get the fallback organizational domain of a domain.
 * This functions fetches the Public Suffix List and caches its latest result.
 *
 * @param string $domain The domain to process.
 * @return string
 */
function fallback_domain( $domain ) {
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
		return null;
	}

	return $org_domain;
}
