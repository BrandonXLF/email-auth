<?php
/**
 * Custom DNS Resolver for SPFLib.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin\SPF;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Exceptions are not escaped since they are used by SPFLib. Instead, all output from SPFLib should be escaped.
// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped

/**
 * Custom DNS Resolver for SPFLib.
 */
class DNSResolver implements \SPFLib\DNS\Resolver {
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
	 * {@inheritdoc}
	 *
	 * @param string $domain The domain name to query for TXT records.
	 * @return string[]
	 *
	 * @throws \SPFLib\Exception\DNSResolutionException If the DNS resolution fails.
	 */
	public function getTXTRecords( $domain ): array {
		try {
			return array_map(
				function ( \Net_DNS2_RR_TXT $record ) {
					return implode( '', $record->text );
				},
				$this->resolver->query( $domain, 'TXT' )->answer
			);
		} catch ( \Net_DNS2_Exception $e ) {
			throw new \SPFLib\Exception\DNSResolutionException(
				$domain,
				"Failed to get the TXT records for {$domain}: " . $e->getMessage()
			);
		}
	}

	/**
	 * {@inheritdoc}
	 *
	 * @param string $domain The domain to get IP addresses for.
	 * @return \IPLib\Address\AddressInterface[]
	 *
	 * @throws \SPFLib\Exception\DNSResolutionException If the DNS resolution fails.
	 */
	public function getIPAddressesFromDomainName( string $domain ): array {
		try {
			return array_map(
				function ( \Net_DNS2_RR_A|\Net_DNS2_RR_AAAA $record ) {
					return \IPLIB\Factory::parseAddressString( $record->address );
				},
				array_merge(
					$this->resolver->query( $domain, 'A' )->answer,
					$this->resolver->query( $domain, 'AAAA' )->answer
				)
			);
		} catch ( \Net_DNS2_Exception $e ) {
			throw new \SPFLib\Exception\DNSResolutionException(
				$domain,
				"Failed to get the A/AAAA records for {$domain}: " . $e->getMessage()
			);
		}
	}

	/**
	 * {@inheritdoc}
	 *
	 * @param string $domain The domain to get MX records for.
	 * @return string[]
	 *
	 * @throws \SPFLib\Exception\DNSResolutionException If the DNS resolution fails.
	 */
	public function getMXRecords( string $domain ): array {
		try {
			return array_map(
				function ( \Net_DNS2_RR_MX $record ) {
					return $record->exchange;
				},
				$this->resolver->query( $domain, 'MX' )->answer
			);
		} catch ( \Net_DNS2_Exception $e ) {
			throw new \SPFLib\Exception\DNSResolutionException(
				$domain,
				"Failed to get the MX records for {$domain}: " . $e->getMessage()
			);
		}
	}

	/**
	 * {@inheritdoc}
	 *
	 * @param string $domain The domain to get PTR records for.
	 * @return string[]
	 *
	 * @throws \SPFLib\Exception\DNSResolutionException If the DNS resolution fails.
	 */
	public function getPTRRecords( string $domain ): array {
		try {
			return array_map(
				function ( \Net_DNS2_RR_PTR $record ) {
					return $record->ptrdname;
				},
				$this->resolver->query( $domain, 'PTR' )->answer
			);
		} catch ( \Net_DNS2_Exception $e ) {
			throw new \SPFLib\Exception\DNSResolutionException(
				$domain,
				"Failed to get the PTR records for {$domain}: " . $e->getMessage()
			);
		}
	}

	/**
	 * {@inheritdoc}
	 *
	 * @param \IPLib\Address\AddressInterface $ip The IP address to resolve to a domain name.
	 * @return string
	 *
	 * @throws \SPFLib\Exception\DNSResolutionException If the DNS resolution fails.
	 */
	public function getDomainNameFromIPAddress( \IPLib\Address\AddressInterface $ip ): string {
		// Not used by the plugin anywhere, so this is sufficient.
		return gethostbyaddr( (string) $ip );
	}
}
