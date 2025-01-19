<?php
/**
 * Tests for check_dmarc.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

require_once dirname( __DIR__ ) . '/vendor/autoload.php';
require_once dirname( __DIR__ ) . '/includes/utils/common.php';
require_once dirname( __DIR__ ) . '/includes/utils/check-dmarc.php';

use PHPUnit\Framework\TestCase;

/**
 * Tests for check_dmarc.
 */
class CheckDmarcTest extends TestCase {
	/**
	 * Make a TXT record resolver that has a override for a domain.
	 *
	 * @param string $domain The domain to override.
	 * @param array  ...$res The result to return for the domain.
	 * @return callable
	 */
	public function makeTxtResolver( $domain = 'example.com', ...$res ) {
		return function ( $actual_domain ) use ( $domain, $res ) {
			if ( $domain !== $actual_domain ) {
				return DNSTagValue\get_txt_record( $domain );
			}

			return $res;
		};
	}

	/**
	 * Make a resolver that returns the fallback organizational domain for the domain being used in the test.
	 *
	 * @param string $fallback_domain The fallback domain.
	 * @return callable
	 */
	public function makeFallbackResolver( $fallback_domain = null ) {
		return function () use ( $fallback_domain ) {
			return $fallback_domain;
		};
	}

	public function testMinimal() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.example.com', [ 'txt' => 'v=DMARC1' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'example.com', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => 'partial',
				'warnings' => [
					'DMARC will pass regardless of DKIM and SPF alignment. Add a <code>p=quarantine</code> or <code>p=reject</code> term.',
				],
				'infos'    => [
					'DMARC will still pass if the DKIM domain and "From" domain share a common registered domain.',
					'DMARC will still pass if the bounce domain and "From" domain share a common registered domain.',
				],
				'footnote' => null,
				'org'      => null,
			],
			$res
		);
	}

	public function testQuarantine() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.example.com', [ 'txt' => 'v=DMARC1; p=quarantine' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'example.com', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'warnings' => [],
				'infos'    => [
					'Failures will be treated as suspicious, but will not be outright rejected.',
					'DMARC will still pass if the DKIM domain and "From" domain share a common registered domain.',
					'DMARC will still pass if the bounce domain and "From" domain share a common registered domain.',
				],
				'footnote' => 'DMARC only passes if at least one of <a href="#dkim">DKIM</a> and <a href="#spf">SPF</a> passes domain alignment.',
				'org'      => null,
			],
			$res
		);
	}

	public function testReject() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.example.com', [ 'txt' => 'v=DMARC1; p=reject' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'example.com', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => true,
				'warnings' => [],
				'infos'    => [
					'DMARC will still pass if the DKIM domain and "From" domain share a common registered domain.',
					'DMARC will still pass if the bounce domain and "From" domain share a common registered domain.',
				],
				'footnote' => 'DMARC only passes if at least one of <a href="#dkim">DKIM</a> and <a href="#spf">SPF</a> passes domain alignment.',
				'org'      => null,
			],
			$res
		);
	}

	public function testStrictDKIM() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.example.com', [ 'txt' => 'v=DMARC1; adkim=s' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'example.com', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => 'partial',
				'warnings' => [
					'DMARC will pass regardless of DKIM and SPF alignment. Add a <code>p=quarantine</code> or <code>p=reject</code> term.',
				],
				'infos'    => [
					'DMARC will still pass if the bounce domain and "From" domain share a common registered domain.',
				],
				'footnote' => null,
				'org'      => null,
			],
			$res
		);
	}

	public function testStrictAll() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.example.com', [ 'txt' => 'v=DMARC1; adkim=s; aspf=s' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'example.com', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => 'partial',
				'warnings' => [
					'DMARC will pass regardless of DKIM and SPF alignment. Add a <code>p=quarantine</code> or <code>p=reject</code> term.',
				],
				'infos'    => [],
				'footnote' => null,
				'org'      => null,
			],
			$res
		);
	}

	public function testPct() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.example.com', [ 'txt' => 'v=DMARC1; p=reject; pct=40' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'example.com', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => 'partial',
				'warnings' => [
					'DMARC will only fail for 40% of failures.',
				],
				'infos'    => [
					'DMARC will still pass if the DKIM domain and "From" domain share a common registered domain.',
					'DMARC will still pass if the bounce domain and "From" domain share a common registered domain.',
				],
				'footnote' => 'DMARC only passes if at least one of <a href="#dkim">DKIM</a> and <a href="#spf">SPF</a> passes domain alignment.',
				'org'      => null,
			],
			$res
		);
	}

	public function testMultipleRecords() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.example.com', [ 'txt' => 'v=DMARC1; p=reject' ], [ 'txt' => 'v=DMARC1; p=none' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'example.com', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Multiple TXT records found, only one should be present.',
				'warnings' => [],
				'infos'    => [],
				'footnote' => null,
				'org'      => null,
			],
			$res
		);
	}

	public function testNoRecord() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.example.com' );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'example.com', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'No TXT record found.',
				'warnings' => [],
				'infos'    => [],
				'footnote' => null,
				'org'      => null,
			],
			$res
		);
	}

	public function testInvalidDomain() {
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( '+', null, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Could not retrieve DNS record. dns_get_record(): DNS Query failed',
				'warnings' => [],
				'infos'    => [],
				'footnote' => null,
				'org'      => null,
			],
			$res
		);
	}

	public function testSubDomain() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.existent.example.com', [ 'txt' => 'v=DMARC1' ] );
		$f_resolve = $this->makeFallbackResolver( 'example.com' );
		$res       = check_dmarc( 'existent.example.com', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => 'partial',
				'warnings' => [
					'DMARC will pass regardless of DKIM and SPF alignment. Add a <code>p=quarantine</code> or <code>p=reject</code> term.',
				],
				'infos'    => [
					'DMARC will still pass if the DKIM domain and "From" domain share a common registered domain.',
					'DMARC will still pass if the bounce domain and "From" domain share a common registered domain.',
				],
				'footnote' => null,
				'org'      => 'example.com',
			],
			$res
		);
	}

	public function testOrgFallback() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.example.com', [ 'txt' => 'v=DMARC1' ] );
		$f_resolve = $this->makeFallbackResolver( 'example.com' );
		$res       = check_dmarc( 'non-existent.example.com', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => 'partial',
				'warnings' => [
					'DMARC will pass regardless of DKIM and SPF alignment. Add a <code>p=quarantine</code> or <code>p=reject</code> term.',
				],
				'infos'    => [
					'DMARC will still pass if the DKIM domain and "From" domain share a common registered domain.',
					'DMARC will still pass if the bounce domain and "From" domain share a common registered domain.',
				],
				'footnote' => null,
				'org'      => 'example.com',
			],
			$res
		);
	}
}
