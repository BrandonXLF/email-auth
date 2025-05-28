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

/**
 * DNS TXT record resolver for DNS Tag-Value.
 */
class TxtResolver {
	/**
	 * The DNS resolver instance.
	 *
	 * @var \Net_DNS2_Resolver
	 */
	private $resolver;

	/**
	 * Constructor.
	 *
	 * @param \Net_DNS2_Resolver $resolver The DNS resolver instance.
	 */
	public function __construct( ?\Net_DNS2_Resolver $resolver = null ) {
		$this->resolver = $resolver ?? new \Net_DNS2_Resolver();
	}

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
			throw new MissingException( 'Could not retrieve DNS record. ' . esc_html( $e->getMessage() ) );
		}
	}
}
