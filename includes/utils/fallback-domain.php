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
 * @return array{string|null, string|null} The fallback domain and a warning string.
 */
function fallback_domain( $domain ) {
	$org_domain_map = get_transient( 'eauth_org_domain_map' ) ?: [];
	$org_domain     = $org_domain_map[ $domain ] ?? null;
	$warning        = null;

	if ( ! $org_domain ) {
		$res = wp_remote_get( 'https://publicsuffix.org/list/public_suffix_list.dat' );

		if ( is_wp_error( $res ) ) {
			$text    = '';
			$warning = "Failed to get public suffix list.\n" . $res->get_error_message();
		} elseif ( 200 !== $res['response']['code'] ) {
			$text    = '';
			$warning = "Failed to get public suffix list.\nHTTP code: " . $res['response']['code'];
		} else {
			$text = $res['body'];
		}

		try {
			$list = \Pdp\Rules::fromString( $text );
		} catch ( \Exception $e ) {
			$list    = \Pdp\Rules::fromString( '' );
			$warning = "Could not process public suffix list.\n" . $e->getMessage();
		}

		$result     = $list->resolve( $domain );
		$org_domain = $result->registrableDomain()->toString();

		if ( ! $warning ) {
			set_transient(
				'eauth_org_domain_map',
				[ $domain => $org_domain ],
				24 * HOUR_IN_SECONDS
			);
		}
	}

	if ( $org_domain === $domain ) {
		$org_domain = null;
	}

	return [ $org_domain, $warning ];
}
