<?php
/**
 * DNS TXT record resolver for DNS Tag-Value.
 *
 * @package Email Auth
 * @subpackage DNS Tag-Value
 */

namespace EmailAuthPlugin\DNSTagValue;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/../dns/class-netdns2wrapper.php';

/**
 * DNS TXT record resolver for DNS Tag-Value.
 */
class TxtResolver extends \EmailAuthPlugin\DNS\NetDns2Wrapper {
	/**
	 * Get TXT records for a given domain.
	 *
	 * @param string $domain The domain name to query for TXT records.
	 * @throws MissingException If the DNS resolution fails.
	 * @return string[]
	 */
	public function get_records( $domain ) {
		try {
			return array_map(
				function ( \Net_DNS2_RR_TXT $record ) {
					return implode( '', $record->text );
				},
				$this->resolver->query( $domain, 'TXT' )->answer
			);
		} catch ( \Net_DNS2_Exception $e ) {
			require_once __DIR__ . '/class-missingexception.php';
			throw new MissingException( 'Could not retrieve DNS record. ' . $e->getMessage() );
		}
	}
}
