<?php
/**
 * Stub declarations for WordPress PHPUnit scaffold (IDE / static analysis).
 *
 * @package Email Auth
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedClassFound

if ( ! class_exists( 'WP_UnitTestCase', false ) ) {
	/**
	 * Minimal stand-in for wordpress-tests-lib when it is not installed locally.
	 */
	class WP_UnitTestCase extends \PHPUnit\Framework\TestCase {

		/**
		 * WordPress test case setup (snake_case wrapper used by integration tests).
		 */
		public function set_up(): void {
		}

		/**
		 * WordPress test case teardown (snake_case wrapper used by integration tests).
		 */
		public function tear_down(): void {
		}
	}
}
