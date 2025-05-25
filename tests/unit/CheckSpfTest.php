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
	 * The domain to override.
	 *
	 * @var string
	 */
	private string $domain;

	/**
	 * The text of the records to return.
	 *
	 * @var array
	 */
	private array $res;

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
	public function getTXTRecords( $domain ): array {
		if ( $this->domain === $domain ) {
			return $this->res;
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
				'cur_rec'      => 'v=spf1',
				'cur_validity' => [],
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
				'cur_rec'      => 'v=spf1 ~all',
				'cur_validity' => [],
				'rec_dns'      => 'v=spf1 a:server.domain ~all',
				'rec_reasons'  => [
					[
						'level' => 'error',
						'desc'  => 'Website host (domain.test or 192.0.2.0) is not included in a pass case of the SPF record.',
					],
				],
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
				'cur_rec'      => 'v=spf1 -all',
				'cur_validity' => [],
				'rec_dns'      => 'v=spf1 a:server.domain -all',
				'rec_reasons'  => [
					[
						'level' => 'error',
						'desc'  => 'Website host (domain.test or 192.0.2.0) is not included in a pass case of the SPF record.',
					],
				],
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
				'cur_rec'      => 'v=spf1 ip4:192.0.2.0 -all',
				'cur_validity' => [],
				'rec_dns'      => null,
				'rec_reasons'  => [],
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
				'cur_rec'      => 'v=spf1 a:google.com -all',
				'cur_validity' => [],
				'rec_dns'      => null,
				'rec_reasons'  => [],
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
				'reason'       => 'SPF check did not pass.',
				'code'         => 'permerror',
				'code_reasons' => [
					[
						'level' => 'error',
						'desc'  => 'The SPF record contains an unrecognized term: waaaaaa',
					],
				],
				'cur_rec'      => '',
				'cur_validity' => [],
				'rec_dns'      => null,
				'rec_reasons'  => [],
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
				'cur_rec'      => 'v=spf1 a:google.com -all ip4:127.0.0.1',
				'cur_validity' => [
					[
						'level' => 'warning',
						'desc'  => '&#039;all&#039; should be the last mechanism (any other mechanism will be ignored)',
					],
				],
				'rec_dns'      => null,
				'rec_reasons'  => [],
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
				'cur_rec'      => 'v=spf1 a:google.com',
				'cur_validity' => [],
				'rec_dns'      => 'v=spf1 a:google.com ~all',
				'rec_reasons'  => [
					[
						'level' => 'warning',
						'desc'  => 'An <code>~all</code> or <code>-all</code> term is recommended to (soft) fail all other servers.',
					],
				],
			],
			$res
		);
	}
}
