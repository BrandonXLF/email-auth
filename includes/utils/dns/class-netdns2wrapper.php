<?php
/**
 * Wrapper around Net_DNS2_Resolver.
 *
 * @package Email Auth
 * @subpackage DNS
 */

namespace EmailAuthPlugin\DNS;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wrapper around Net_DNS2_Resolver.
 */
abstract class NetDns2Wrapper {
	/**
	 * The DNS resolver instance.
	 *
	 * @var \Net_DNS2_Resolver
	 */
	protected $resolver;

	/**
	 * Constructor.
	 *
	 * @param \Net_DNS2_Resolver $resolver The DNS resolver instance.
	 */
	public function __construct( ?\Net_DNS2_Resolver $resolver = null ) {
		$this->resolver = $resolver ?? new \Net_DNS2_Resolver();
	}
}
