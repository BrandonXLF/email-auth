<?php
/**
 * Test TXT resolver that overrides the TXT records for a domain.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

require_once dirname( __DIR__ ) . '/includes/utils/dns-tag-value/class-txtresolver.php';

/**
 * Test TXT resolver that overrides the TXT records for a domain.
 */
class TestTxtResolver extends DNSTagValue\TxtResolver {
	/**
	 * Name of domain to override.
	 *
	 * @var string
	 */
	private string $domain;

	/**
	 * Array of records to return for the domain.
	 *
	 * @var array
	 */
	private array $res = [];

	/**
	 * Constructor that accepts an override for a domain.
	 *
	 * @param string $domain The domain to override.
	 * @param array  ...$res The text of the records to return.
	 */
	public function __construct( $domain, ...$res ) {
		$this->domain = $domain;
		$this->res    = $res;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param string $domain The domain to get TXT records for.
	 * @return string[]
	 */
	public function get_records( $domain ): array {
		if ( $this->domain !== $domain ) {
			return []; // Non existent domain.
		}

		return $this->res ?? [];
	}
}
