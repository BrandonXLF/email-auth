<?php
/**
 * Functions to get values based on plugin settings.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

/**
 * Convert the given value to an valid email address, defaulting to the current domain.
 *
 * @param string $maybe_addr Either a username or an email address.
 * @return string
 */
function as_address( $maybe_addr ) {
	$parts = explode( '@', $maybe_addr, 2 );

	if ( ! isset( $parts[1] ) ) {
		return $maybe_addr . '@' . get_domain();
	} else {
		return $maybe_addr;
	}
}

/**
 * Extract the domain from the given email address.
 *
 * @param string $addr The email address.
 * @return string
 */
function extract_domain( $addr ) {
	$parts = explode( '@', $addr, 2 );
	return $parts[1];
}

/**
 * Get the from address that should be used.
 *
 * @return string|null
 */
function get_from_address() {
	$addr = get_option( 'eauth_from_address' );
	if ( '' !== $addr ) {
		return as_address( $addr );
	}

	return null;
}

/**
 * Get the bounce address that should be used.
 *
 * @param string $from The from address to use if known.
 * @return string|null
 */
function get_bounce_address( $from = null ) {
	$mode = get_option( 'eauth_bounce_address_mode' );

	if ( 'from' === $mode ) {
		return $from ?? get_from_address();
	}

	if ( 'custom' === $mode ) {
		return as_address( get_option( 'eauth_bounce_address' ) );
	}

	return ini_get( 'sendmail_from' ) ?: null;
}

/**
 * Get the DKIM domain that should be used.
 *
 * @param string $from The from address to use if known.
 * @param string $bounce The bounce address to use if known.
 * @return string|null
 */
function get_dkim_domain( $from = null, $bounce = null ) {
	$mode   = get_option( 'eauth_dkim_domain' );
	$from ??= get_from_address();

	if ( 'wp' === $mode ) {
		return get_domain();
	}

	if ( 'from' === $mode ) {
		return extract_domain( $from );
	}

	if ( 'bounce' === $mode ) {
		return extract_domain( $bounce ?? get_bounce_address( $from ) );
	}

	if ( 'custom' === $mode ) {
		return get_option( 'eauth_dkim_domain_custom' );
	}

	return null;
}