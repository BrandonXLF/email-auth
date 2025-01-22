<?php
/**
 * Tests for check_dkim_dns.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

require_once dirname( __DIR__ ) . '/vendor/autoload.php';
require_once dirname( __DIR__ ) . '/includes/utils/common.php';
require_once dirname( __DIR__ ) . '/includes/utils/check-dkim.php';

use PHPUnit\Framework\TestCase;

/**
 * Tests for check_dkim_dns.
 */
class CheckDkimTest extends TestCase {
	/**
	 * Make a TXT record resolver that supports one domain.
	 *
	 * @param string $domain The domain.
	 * @param array  ...$res The result to return for the domain.
	 * @return callable
	 */
	public function makeTxtResolver( $domain = 'test._domainkey.example.com', ...$res ) {
		return function ( $actual_domain ) use ( $domain, $res ) {
			if ( $domain !== $actual_domain ) {
				throw new \Exception( 'TXT resolver invoked on ' . $actual_domain . ', expected ' . $domain );
			}

			return $res;
		};
	}

	public function testNormal() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.example.com', [ 'txt' => 'p=PUBLIC_KEY' ] );
		$res     = check_dkim_dns( 'test._domainkey.example.com', 'PUBLIC_KEY', $resolve );

		$this->assertEquals( [ 'pass' => true ], $res );
	}

	public function testEntries() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.example.com', [ 'entries' => [ 'v=DKIM1; p=PUBLIC', '_KEY' ] ] );
		$res     = check_dkim_dns( 'test._domainkey.example.com', 'PUBLIC_KEY', $resolve );

		$this->assertEquals( [ 'pass' => true ], $res );
	}

	public function testMissingKey() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.example.com', [ 'txt' => 'v=DKIM1; a=b;' ] );
		$res     = check_dkim_dns( 'test._domainkey.example.com', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'Public key is missing.',
			],
			$res
		);
	}

	public function testIncorrectKey() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.example.com', [ 'txt' => 'v=DKIM1; p=PRIVATE_KEY' ] );
		$res     = check_dkim_dns( 'test._domainkey.example.com', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'Public key is incorrect.',
			],
			$res
		);
	}

	public function testMultipleRecords() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.example.com', [ 'txt' => 'v=DKIM1; p=PUBLIC_KEY' ], [ 'txt' => 'v=DKIM1; p=PUBLIC_KEY' ] );
		$res     = check_dkim_dns( 'test._domainkey.example.com', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'Multiple TXT records found, only one should be present.',
			],
			$res
		);
	}

	public function testNoRecord() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.example.com' );
		$res     = check_dkim_dns( 'test._domainkey.example.com', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'No TXT record found.',
			],
			$res
		);
	}
}
