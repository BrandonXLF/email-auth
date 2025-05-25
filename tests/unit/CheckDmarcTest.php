<?php
/**
 * Tests for check_dmarc.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

require_once dirname( dirname( __DIR__ ) ) . '/includes/utils/check-dmarc.php';

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
	public function makeTxtResolver( $domain = 'domain.test', ...$res ) {
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
	 * @param string $warning Warning to simulate.
	 * @return callable
	 */
	public function makeFallbackResolver( $fallback_domain = null, $warning = null ) {
		return function () use ( $fallback_domain, $warning ) {
			return [ $fallback_domain, $warning ];
		};
	}

	public function testMinimal() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'v=DMARC1' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

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
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testEntries() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'entries' => [ 'v=DMA', 'RC1' ] ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

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
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testQuarantine() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'v=DMARC1; p=quarantine' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

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
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testReject() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'v=DMARC1; p=reject' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

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
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testStrictDKIM() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'v=DMARC1; adkim=s' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

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
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testStrictAll() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'v=DMARC1; adkim=s; aspf=s' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => 'partial',
				'warnings' => [
					'DMARC will pass regardless of DKIM and SPF alignment. Add a <code>p=quarantine</code> or <code>p=reject</code> term.',
				],
				'infos'    => [],
				'footnote' => null,
				'org'      => null,
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testPct() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'v=DMARC1; p=reject; pct=40' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

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
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testMultipleRecords() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'v=DMARC1; p=reject' ], [ 'txt' => 'v=DMARC1; p=none' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'Multiple TXT records found, only one should be present.',
				'warnings' => [],
				'infos'    => [],
				'footnote' => null,
				'org'      => null,
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testNoRecord() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test' );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'No TXT record found.',
				'warnings' => [],
				'infos'    => [],
				'footnote' => null,
				'org'      => null,
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testSubDomain() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.existent.domain.test', [ 'txt' => 'v=DMARC1' ] );
		$f_resolve = $this->makeFallbackResolver( 'domain.test' );
		$res       = check_dmarc( 'existent.domain.test', $t_resolve, $f_resolve );

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
				'org'      => 'domain.test',
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testOrgFallback() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'v=DMARC1' ] );
		$f_resolve = $this->makeFallbackResolver( 'domain.test' );
		$res       = check_dmarc( 'non-existent.domain.test', $t_resolve, $f_resolve );

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
				'org'      => 'domain.test',
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testFallbackWarning() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.test.domain.test', [ 'txt' => 'v=DMARC1' ] );
		$f_resolve = $this->makeFallbackResolver( 'domain.test', 'Warning!' );
		$res       = check_dmarc( 'test.domain.test', $t_resolve, $f_resolve );

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
				'org'      => 'domain.test',
				'orgFail'  => 'Warning!',
			],
			$res
		);
	}

	public function testBadVersion() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'v=DMARC2' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'No TXT record found.',
				'warnings' => [ 'Potential record ignored: Version identifier must be v=DMARC1.' ],
				'infos'    => [],
				'footnote' => null,
				'org'      => null,
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testMissingVersion() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'p=reject' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'No TXT record found.',
				'warnings' => [ 'Potential record ignored: Version identifier (v=DMARC1) is missing.' ],
				'infos'    => [],
				'footnote' => null,
				'org'      => null,
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testVersionFirst() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'p=reject; v=DMARC1' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => false,
				'reason'   => 'No TXT record found.',
				'warnings' => [ 'Potential record ignored: First tag must be the version identifier (v).' ],
				'infos'    => [],
				'footnote' => null,
				'org'      => null,
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testIgnoredRecords() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'v=DMARC2; p=none' ], [ 'txt' => 'v=DMARC2; p=quarantine' ], [ 'txt' => 'v=DMARC1; p=reject' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

		$this->assertEquals(
			[
				'pass'     => 'partial',
				'warnings' => [
					'Potential record ignored: Version identifier must be v=DMARC1.',
					'Potential record ignored: Version identifier must be v=DMARC1.'
				],
				'infos'    => [
					'DMARC will still pass if the DKIM domain and "From" domain share a common registered domain.',
					'DMARC will still pass if the bounce domain and "From" domain share a common registered domain.',
				],
				'footnote' => 'DMARC only passes if at least one of <a href="#dkim">DKIM</a> and <a href="#spf">SPF</a> passes domain alignment.',
				'org'      => null,
				'orgFail'  => null,
			],
			$res
		);
	}

	public function testTrailingSemicolon() {
		$t_resolve = $this->makeTxtResolver( '_dmarc.domain.test', [ 'txt' => 'v=DMARC1; p=none;' ] );
		$f_resolve = $this->makeFallbackResolver();
		$res       = check_dmarc( 'domain.test', $t_resolve, $f_resolve );

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
				'orgFail'  => null,
			],
			$res
		);
	}
}
