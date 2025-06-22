<?php
/**
 * Polyfills for tests.
 *
 * @package Email Auth
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound

if ( ! function_exists( 'esc_html' ) ) {
	/**
	 * Dummy esc_html function for unit tests.
	 *
	 * @param string $text The text to escape.
	 * @return string The escaped text.
	 */
	function esc_html( $text ) {
		return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
	}
}
