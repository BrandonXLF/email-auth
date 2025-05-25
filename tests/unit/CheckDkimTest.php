<?php
/**
 * Tests for check_dkim_dns.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

require_once dirname( dirname( __DIR__ ) ) . '/includes/utils/check-dkim.php';

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
	public function makeTxtResolver( $domain = 'test._domainkey.domain.test', ...$res ) {
		return function ( $actual_domain ) use ( $domain, $res ) {
			if ( $domain !== $actual_domain ) {
				throw new \Exception( 'TXT resolver invoked on ' . $actual_domain . ', expected ' . $domain );
			}

			return $res;
		};
	}

	public function testBasic() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'txt' => 'p=PUBLIC_KEY' ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'warnings' => [],
			],
			$res
		);
	}

	public function testEntries() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'entries' => [ 'v=DKIM1; p=PUBLIC', '_KEY' ] ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
		[
				'pass'     => true,
				'warnings' => [],
			],
			$res
		);
	}

	public function testNonStandard() {
		$resolve = $this->makeTxtResolver( 'te_st._domainkey.domain.test', [ 'txt' => 'v=DKIM1; p=PUBLIC_KEY' ] );
		$res     = check_dkim_dns( 'te_st', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => 'partial',
				'warnings' => [ 'Selector name is non-standard.' ],
			],
			$res
		);
	}

	public function testMissingKey() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'txt' => 'v=DKIM1; a=b' ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'Public key is missing.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testIncorrectKey() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'txt' => 'v=DKIM1; p=PRIVATE_KEY' ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'Public key is incorrect.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testMultipleRecords() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'txt' => 'v=DKIM1; p=PUBLIC_KEY' ], [ 'txt' => 'v=DKIM1; p=PUBLIC_KEY' ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'Multiple TXT records found, only one should be present.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testNoRecord() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'No TXT record found.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testServiceType() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'txt' => 'v=DKIM1; p=PUBLIC_KEY; s=phone:email' ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => true,
				'warnings' => [],
			],
			$res
		);
	}

	public function testServiceTypeUnsupported() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'txt' => 'v=DKIM1; p=PUBLIC_KEY; s=phone' ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'Record service type must include email (or *).',
				'warnings' => [],
			],
			$res
		);
	}

	public function testBadVersion() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'txt' => 'v=DKIM2; p=PUBLIC_KEY' ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'Version identifier must be v=DKIM1 if present.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testVersionFirst() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'txt' => 'p=PUBLIC_KEY; v=DKIM1' ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'Version identifier must be the first tag if present.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testTestMode() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'txt' => 'v=DKIM1; p=PUBLIC_KEY; t=y' ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => true,
				'warnings' => [ 'Test mode is enabled, DKIM policy might be ignored.' ],
			],
			$res
		);
	}

	public function testMultipleWarnings() {
		$resolve = $this->makeTxtResolver( 'te_st._domainkey.domain.test', [ 'txt' => 'v=DKIM1; p=PUBLIC_KEY; t=y' ] );
		$res     = check_dkim_dns( 'te_st', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => true,
				'warnings' => [ 'Test mode is enabled, DKIM policy might be ignored.', 'Selector name is non-standard.' ],
			],
			$res
		);
	}

	public function testTrailingSemicolon() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'txt' => 'v=DKIM1; p=PUBLIC_KEY;' ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => true,
				'warnings' => [],
			],
			$res
		);
	}

	public function testMalformedRecord() {
		$resolve = $this->makeTxtResolver( 'test._domainkey.domain.test', [ 'txt' => 'v=DKIM1; p=PUBLIC_KEY; malformed' ] );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'   => false,
				'reason' => 'Malformed tag-value pair.',
				'warnings' => [],
			],
			$res
		);
	}
}
