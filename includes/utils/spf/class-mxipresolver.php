<?php
/**
 * Try to resolve the primary inbound mail server for a domain.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin\SPF;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Try to resolve the primary inbound mail server for a domain.
 */
class MxIpResolver {
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
	 * Get the IP address of the given domain.
	 *
	 * @param string $domain The domain name to query for A/AAAA records.
	 * @return string|null
	 */
	private function get_ip( $domain ) {
		$records = null;

		try {
			$records = $this->resolver->query( $domain, 'A' )->answer;
		} catch ( \Net_DNS2_Exception $_ ) {
			try {
				$records = $this->resolver->query( $domain, 'AAAA' )->answer;
			} catch ( \Net_DNS2_Exception $_ ) {
				$records = [];
			}
		}

		return ! empty( $records ) ? $records[0]->address : null;
	}

	/**
	 * Try to get the IP addresses of the primary inbound mail server for a domain.
	 *
	 * @param string $domain The domain name to query for TXT records.
	 * @return string|null
	 */
	public function get_mx_ip( $domain ) {
		$check = null;

		try {
			$records = $this->resolver->query( $domain, 'MX' )->answer;

			$primary = array_reduce(
				$records,
				function ( $acc, \Net_DNS2_RR_MX $record ) {
					return ( null === $acc || $record->preference < $acc->preference ) ? $record : $acc;
				}
			);

			$check = $primary ? $primary->exchange : $domain;
		} catch ( \Net_DNS2_Exception $_ ) {
			$check = $domain;
		}

		return $this->get_ip( $check );
	}
}
