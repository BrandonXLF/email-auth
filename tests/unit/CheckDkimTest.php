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

$eauth_dkim_test_private_key = file_get_contents( dirname( __DIR__ ) . '/test.pem' );
$eauth_dkim_test_public_key  = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsayYTCBNGnsly/w7uqpu6tyPU0rK/aN265+JX6H52tx23JV1Kn0GNC0kNQASXme/cjccIChcKjbMSb6MQZSexj1R3+SzB16rK2Zd9ymVBdBs93wVBz+RxawPi/At6+IkCFz/xoeJdi3nyqsJFKsegsYzGvvpQI49ldqpsDkGxArElqgxiQA+nTDgpcJx+U0EcB1w8jldUtqWzkpX2RKqVzzRsKgPwgJD0oZtbK3dwnry7zswIaXb4TjDGsprTR0THQjTEndAg5K28viqtVSt40HqTDQ25RjANCUEnpi0PnycP9nfB86OJ0TC9KIInn0NPxosG7Ov4V0NAaM03q4VAQIDAQAB';

/**
 * Tests for check_dkim_dns.
 */
class CheckDkimTest extends TestCase {
	public function testBasic() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', "v=DKIM1; p=$eauth_dkim_test_public_key" );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'reason'   => null,
				'record'   => "v=DKIM1; p=$eauth_dkim_test_public_key",
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [],
			],
			$res
		);
	}

	public function testNonStandard() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'te_st._domainkey.domain.test', "v=DKIM1; p=$eauth_dkim_test_public_key" );
		$res     = check_dkim_dns( 'te_st', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => 'partial',
				'reason'   => null,
				'record'   => "v=DKIM1; p=$eauth_dkim_test_public_key",
				'host'     => 'te_st._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [ 'Selector name is non-standard.' ],
			],
			$res
		);
	}

	public function testMissingKey() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM1; a=b' );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Public key is missing.',
				'record'   => 'v=DKIM1; a=b',
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [],
			],
			$res
		);
	}

	public function testIncorrectKey() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', 'v=DKIM1; p=INCORRECT_KEY' );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Public key is incorrect.',
				'record'   => 'v=DKIM1; p=INCORRECT_KEY',
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [],
			],
			$res
		);
	}

	public function testMultipleRecords() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', "v=DKIM1; p=$eauth_dkim_test_public_key", "v=DKIM1; p=$eauth_dkim_test_public_key" );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Multiple TXT records found, only one should be present.',
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [],
			],
			$res
		);
	}

	public function testNoRecord() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test' );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'No TXT record found.',
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [],
			],
			$res
		);
	}

	public function testServiceType() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', "v=DKIM1; p=$eauth_dkim_test_public_key; s=phone:email" );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'reason'   => null,
				'record'   => "v=DKIM1; p=$eauth_dkim_test_public_key; s=phone:email",
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [],
			],
			$res
		);
	}

	public function testServiceTypeUnsupported() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', "v=DKIM1; p=$eauth_dkim_test_public_key; s=phone" );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Record service type must include email (or *).',
				'record'   => "v=DKIM1; p=$eauth_dkim_test_public_key; s=phone",
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [],
			],
			$res
		);
	}

	public function testBadVersion() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', "v=DKIM2; p=$eauth_dkim_test_public_key" );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Version identifier must be v=DKIM1 if present.',
				'record'   => "v=DKIM2; p=$eauth_dkim_test_public_key",
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [],
			],
			$res
		);
	}

	public function testVersionFirst() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', "p=$eauth_dkim_test_public_key; v=DKIM1" );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Version identifier must be the first tag if present.',
				'record'   => "p=$eauth_dkim_test_public_key; v=DKIM1",
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [],
			],
			$res
		);
	}

	public function testTestMode() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', "v=DKIM1; p=$eauth_dkim_test_public_key; t=y" );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'reason'   => null,
				'record'   => "v=DKIM1; p=$eauth_dkim_test_public_key; t=y",
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [ 'Test mode is enabled, DKIM policy might be ignored.' ],
			],
			$res
		);
	}

	public function testMultipleWarnings() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'te_st._domainkey.domain.test', "v=DKIM1; p=$eauth_dkim_test_public_key; t=y" );
		$res     = check_dkim_dns( 'te_st', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'reason'   => null,
				'record'   => "v=DKIM1; p=$eauth_dkim_test_public_key; t=y",
				'host'     => 'te_st._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [ 'Selector name is non-standard.', 'Test mode is enabled, DKIM policy might be ignored.' ],
			],
			$res
		);
	}

	public function testTrailingSemicolon() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', "v=DKIM1; p=$eauth_dkim_test_public_key;" );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'reason'   => null,
				'record'   => "v=DKIM1; p=$eauth_dkim_test_public_key;",
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [],
			],
			$res
		);
	}

	public function testMalformedRecord() {
		global  $eauth_dkim_test_public_key, $eauth_dkim_test_private_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', "v=DKIM1; p=$eauth_dkim_test_public_key; malformed" );
		$res     = check_dkim_dns( 'test', 'domain.test', $eauth_dkim_test_private_key, $resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Malformed tag-value pair.',
				'record'   => "v=DKIM1; p=$eauth_dkim_test_public_key; malformed",
				'host'     => 'test._domainkey.domain.test',
				'dns'      => "v=DKIM1; h=sha256; t=s; p=$eauth_dkim_test_public_key",
				'warnings' => [],
			],
			$res
		);
	}

	public function testBadPrivateKey() {
		global  $eauth_dkim_test_public_key;

		$resolve = new TestTxtResolver( 'test._domainkey.domain.test', "v=DKIM1; p=$eauth_dkim_test_public_key" );
		$res     = check_dkim_dns( 'test', 'domain.test', 'INVALID_PRIVATE_KEY', $resolve );

		$this->assertStringStartsWith(
			'Failed to read private key from store. - OpenSSL error: ',
			$res['reason']
		);

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => $res['reason'], // Checked above.
				'host'     => 'test._domainkey.domain.test',
				'warnings' => [],
			],
			$res
		);
	}
}
