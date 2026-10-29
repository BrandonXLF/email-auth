<?php
/**
 * Stub declarations for WordPress PHPUnit scaffold (IDE / static analysis).
 *
 * @package Email Auth
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound

if ( ! function_exists( 'reset_phpmailer_instance' ) ) {
	/**
	 * Reset the global PHPMailer instance between tests.
	 */
	function reset_phpmailer_instance() {
	}
}

if ( ! function_exists( 'tests_add_filter' ) ) {
	/**
	 * @param string   $hook          Hook name.
	 * @param callable $callback      Callback.
	 * @param int      $priority      Priority.
	 * @param int      $accepted_args Accepted argument count.
	 */
	function tests_add_filter( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
		unset( $hook, $callback, $priority, $accepted_args );
	}
}
