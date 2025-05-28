<?php
/**
 * Tests for check_dkim_dns.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

require_once dirname( dirname( __DIR__ ) ) . '/includes/utils/check-dkim.php';
require_once dirname( __DIR__ ) . '/class-testtxtresolver.php';

use PHPUnit\Framework\TestCase;

/**
 * Tests for check_dkim_dns.
 */
class CheckDkimTest extends TestCase {
	public function testBasic() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM1; p=PUBLIC_KEY' );
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
		$resolve = new TestTxtResolver( 'te_st._domainkey.domain.test', 'v=DKIM1; p=PUBLIC_KEY' );
		$res     = check_dkim_dns( 'te_st', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => 'partial',
				'warnings' => [ 'Selector name is non-standard.' ],
			],
			$res
		);
	}

	public function testMissingKey() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM1; a=b' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Public key is missing.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testIncorrectKey() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM1; p=PRIVATE_KEY' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Public key is incorrect.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testMultipleRecords() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM1; p=PUBLIC_KEY', 'v=DKIM1; p=PUBLIC_KEY' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Multiple TXT records found, only one should be present.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testNoRecord() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'No TXT record found.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testServiceType() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM1; p=PUBLIC_KEY; s=phone:email' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'warnings' => [],
			],
			$res
		);
	}

	public function testServiceTypeUnsupported() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM1; p=PUBLIC_KEY; s=phone' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Record service type must include email (or *).',
				'warnings' => [],
			],
			$res
		);
	}

	public function testBadVersion() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM2; p=PUBLIC_KEY' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Version identifier must be v=DKIM1 if present.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testVersionFirst() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'p=PUBLIC_KEY; v=DKIM1' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Version identifier must be the first tag if present.',
				'warnings' => [],
			],
			$res
		);
	}

	public function testTestMode() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM1; p=PUBLIC_KEY; t=y' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'warnings' => [ 'Test mode is enabled, DKIM policy might be ignored.' ],
			],
			$res
		);
	}

	public function testMultipleWarnings() {
		$resolve = new TestTxtResolver( 'te_st._domainkey.domain.test', 'v=DKIM1; p=PUBLIC_KEY; t=y' );
		$res     = check_dkim_dns( 'te_st', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'warnings' => [ 'Selector name is non-standard.', 'Test mode is enabled, DKIM policy might be ignored.' ],
			],
			$res
		);
	}

	public function testTrailingSemicolon() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM1; p=PUBLIC_KEY;' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'warnings' => [],
			],
			$res
		);
	}

	public function testMalformedRecord() {
		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM1; p=PUBLIC_KEY; malformed' );
		$res     = check_dkim_dns( 'test', 'domain.test', 'PUBLIC_KEY', $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Malformed tag-value pair.',
				'warnings' => [],
			],
			$res
		);
	}
}
