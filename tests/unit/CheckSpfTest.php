<?php
/**
 * Tests for check_spf.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

require_once dirname( dirname( __DIR__ ) ) . '/includes/utils/check-spf.php';

use PHPUnit\Framework\TestCase;

/**
 * DNS resolver that supports overriding the TXT records for a domain.
 */
class TestDnsResolver extends \SPFLib\DNS\StandardResolver {
	/**
	 * Array of domains and results to override.
	 *
	 * @var array
	 */
	private array $overrides = [];

	/**
	 * Constructor that accepts an override for a domain.
	 *
	 * @param string $domain The domain to override.
	 * @param array  ...$res The text of the records to return.
	 */
	public function __construct( $domain, ...$res ) {
		$this->overrides = [
			$domain => $res,
		];
	}

	/**
	 * Add an override for a domain.
	 *
	 * @param mixed $domain The domain to override.
	 * @param array ...$res The text of the records to return.
	 * @return void
	 */
	public function addOverride( $domain, ...$res ) {
		$this->overrides[ $domain ] = $res;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param string $domain The domain to get TXT records for.
	 * @return string[]
	 */
	public function getTXTRecords( $domain ): array {
		if ( isset( $this->overrides[ $domain ] ) ) {
			return $this->overrides[ $domain ];
		}

		return parent::getTXTRecords( $domain );
	}
}

/**
 * Tests for check_spf.
 */
class CheckSpfTest extends TestCase {
	public function testMinimal() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1' );
		$res      = check_spf( 'domain.test', '192.0.2.0', 'server.domain', $resolver );

		$this->assertEquals(
			[
				'pass'         => false,
				'reason'       => 'SPF check did not pass.',
				'code'         => 'neutral',
				'code_reasons' => [
					[
						'level' => 'error',
						'desc'  => 'No mechanism matched and no redirect modifier found.',
					],
				],
				'record'       => 'v=spf1',
				'validity'     => [],
				'rec_dns'      => 'v=spf1 a:server.domain ~all',
				'rec_reasons'  => [
					[
						'level' => 'error',
						'desc'  => 'Website host (domain.test or 192.0.2.0) is not included in a pass case of the SPF record.',
					],
					[
						'level' => 'warning',
						'desc'  => 'An <code>~all</code> or <code>-all</code> term is recommended to (soft) fail all other servers.',
					],
				],
				'server_ip'    => '192.0.2.0',
			],
			$res
		);
	}

	public function testSoftFail() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 ~all' );
		$res      = check_spf( 'domain.test', '192.0.2.0', 'server.domain', $resolver );

		$this->assertEquals(
			[
				'pass'         => false,
				'reason'       => 'SPF check did not pass.',
				'code'         => 'softfail',
				'code_reasons' => [
					[
						'desc' => 'Non-pass caused by: <code>~all</code>',
					],
				],
				'record'       => 'v=spf1 ~all',
				'validity'     => [],
				'rec_dns'      => 'v=spf1 a:server.domain ~all',
				'rec_reasons'  => [
					[
						'level' => 'error',
						'desc'  => 'Website host (domain.test or 192.0.2.0) is not included in a pass case of the SPF record.',
					],
				],
				'server_ip'    => '192.0.2.0',
			],
			$res
		);
	}

	public function testFail() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 -all' );
		$res      = check_spf( 'domain.test', '192.0.2.0', 'server.domain', $resolver );

		$this->assertEquals(
			[
				'pass'         => false,
				'reason'       => 'SPF check did not pass.',
				'code'         => 'fail',
				'code_reasons' => [
					[
						'desc' => 'Non-pass caused by: <code>-all</code>',
					],
				],
				'record'       => 'v=spf1 -all',
				'validity'     => [],
				'rec_dns'      => 'v=spf1 a:server.domain -all',
				'rec_reasons'  => [
					[
						'level' => 'error',
						'desc'  => 'Website host (domain.test or 192.0.2.0) is not included in a pass case of the SPF record.',
					],
				],
				'server_ip'    => '192.0.2.0',
			],
			$res
		);
	}

	public function testPassIp() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 ip4:192.0.2.0 -all' );
		$res      = check_spf( 'domain.test', '192.0.2.0', 'server.domain', $resolver );

		$this->assertEquals(
			[
				'pass'         => true,
				'reason'       => null,
				'code'         => 'pass',
				'code_reasons' => [],
				'record'       => 'v=spf1 ip4:192.0.2.0 -all',
				'validity'     => [],
				'rec_dns'      => null,
				'rec_reasons'  => [],
				'server_ip'    => '192.0.2.0',
			],
			$res
		);
	}

	public function testPassDomain() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 a:google.com -all' );
		$ip       = gethostbyname( 'google.com' );
		$res      = check_spf( 'domain.test', $ip, 'google.com', $resolver );

		$this->assertEquals(
			[
				'pass'         => true,
				'reason'       => null,
				'code'         => 'pass',
				'code_reasons' => [],
				'record'       => 'v=spf1 a:google.com -all',
				'validity'     => [],
				'rec_dns'      => null,
				'rec_reasons'  => [],
				'server_ip'    => $ip,
			],
			$res
		);
	}

	public function testInvalid() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 waaaaaa -all' );
		$ip       = gethostbyname( 'google.com' );
		$res      = check_spf( 'domain.test', $ip, 'google.com', $resolver );

		$this->assertEquals(
			[
				'pass'         => false,
				'reason'       => 'Could not decode SPF record.',
				'code'         => 'permerror',
				'code_reasons' => [
					[
						'level' => 'error',
						'desc'  => 'The SPF record contains an unrecognized term: waaaaaa',
					],
				],
				'validity'     => false,
				'server_ip'    => $ip,
			],
			$res
		);
	}

	public function testInvalidPass() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 a:google.com -all ip4:127.0.0.1' );
		$ip       = gethostbyname( 'google.com' );
		$res      = check_spf( 'domain.test', $ip, 'google.com', $resolver );

		$this->assertEquals(
			[
				'pass'         => 'partial',
				'reason'       => null,
				'code'         => 'pass',
				'code_reasons' => [],
				'record'       => 'v=spf1 a:google.com -all ip4:127.0.0.1',
				'validity'     => [
					[
						'level' => 'warning',
						'desc'  => '&#039;all&#039; should be the last mechanism (any other mechanism will be ignored)',
					],
				],
				'rec_dns'      => null,
				'rec_reasons'  => [],
				'server_ip'    => $ip,
			],
			$res
		);
	}

	public function testRecPass() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 a:google.com' );
		$ip       = gethostbyname( 'google.com' );
		$res      = check_spf( 'domain.test', $ip, 'google.com', $resolver );

		$this->assertEquals(
			[
				'pass'         => 'partial',
				'reason'       => null,
				'code'         => 'pass',
				'code_reasons' => [],
				'record'       => 'v=spf1 a:google.com',
				'validity'     => [],
				'rec_dns'      => 'v=spf1 a:google.com ~all',
				'rec_reasons'  => [
					[
						'level' => 'warning',
						'desc'  => 'An <code>~all</code> or <code>-all</code> term is recommended to (soft) fail all other servers.',
					],
				],
				'server_ip'    => $ip,
			],
			$res
		);
	}

	public function testUnsafeAll() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 a:google.com all' );
		$ip       = gethostbyname( 'google.com' );
		$res      = check_spf( 'domain.test', $ip, 'google.com', $resolver );

		$this->assertEquals(
			[
				'pass'         => 'partial',
				'reason'       => null,
				'code'         => 'pass',
				'code_reasons' => [],
				'record'       => 'v=spf1 a:google.com all',
				'validity'     => [],
				'rec_dns'      => 'v=spf1 a:google.com ~all',
				'rec_reasons'  => [
					[
						'level' => 'warning',
						'desc'  => 'An <code>~all</code> or <code>-all</code> term is recommended to (soft) fail all other servers.',
					],
				],
				'server_ip'    => $ip,
			],
			$res
		);
	}

	public function testMisplacedUnsafeAll() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 all a:google.com' );
		$ip       = gethostbyname( 'google.com' );
		$res      = check_spf( 'domain.test', $ip, 'google.com', $resolver );

		$this->assertEquals(
			[
				'pass'         => 'partial',
				'reason'       => null,
				'code'         => 'pass',
				'code_reasons' => [],
				'record'       => 'v=spf1 all a:google.com',
				'validity'     => [
					[
						'level' => 'warning',
						'desc'  => '&#039;all&#039; should be the last mechanism (any other mechanism will be ignored)',
					],
				],
				'rec_dns'      => 'v=spf1 a:google.com ~all',
				'rec_reasons'  => [
					[
						'level' => 'warning',
						'desc'  => 'An <code>~all</code> or <code>-all</code> term is recommended to (soft) fail all other servers.',
					],
				],
				'server_ip'    => $ip,
			],
			$res
		);
	}

	public function testInclude() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 include:bar.test -all' );
		$resolver->addOverride( 'bar.test', 'v=spf1 a:google.com -all' );

		$ip  = gethostbyname( 'google.com' );
		$res = check_spf( 'domain.test', $ip, 'google.com', $resolver );

		$this->assertEquals(
			[
				'pass'         => true,
				'reason'       => null,
				'code'         => 'pass',
				'code_reasons' => [],
				'record'       => 'v=spf1 include:bar.test -all',
				'validity'     => [],
				'rec_dns'      => null,
				'rec_reasons'  => [],
				'server_ip'    => $ip,
			],
			$res
		);
	}

	public function testMultipleIncludes() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 include:bar.test include:baz.test -all' );
		$resolver->addOverride( 'bar.test', 'v=spf1 a:bing.com -all' );
		$resolver->addOverride( 'baz.test', 'v=spf1 a:google.com -all' );

		$ip  = gethostbyname( 'google.com' );
		$res = check_spf( 'domain.test', $ip, 'google.com', $resolver );

		$this->assertEquals(
			[
				'pass'         => true,
				'reason'       => null,
				'code'         => 'pass',
				'code_reasons' => [],
				'record'       => 'v=spf1 include:bar.test include:baz.test -all',
				'validity'     => [],
				'rec_dns'      => null,
				'rec_reasons'  => [],
				'server_ip'    => $ip,
			],
			$res
		);
	}

	public function testNestedIncludes() {
		$resolver = new TestDnsResolver( 'domain.test', 'v=spf1 include:bar.test -all' );
		$resolver->addOverride( 'bar.test', 'v=spf1 include:baz.test -all' );
		$resolver->addOverride( 'baz.test', 'v=spf1 a:google.com -all' );

		$ip  = gethostbyname( 'google.com' );
		$res = check_spf( 'domain.test', $ip, 'google.com', $resolver );

		$this->assertEquals(
			[
				'pass'         => true,
				'reason'       => null,
				'code'         => 'pass',
				'code_reasons' => [],
				'record'       => 'v=spf1 include:bar.test -all',
				'validity'     => [],
				'rec_dns'      => null,
				'rec_reasons'  => [],
				'server_ip'    => $ip,
			],
			$res
		);
	}
}
