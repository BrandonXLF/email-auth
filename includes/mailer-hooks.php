<?php
/**
 * Hooks that modify wp_mail.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Convert the given value to an valid email adress, defaulting to the current domain.
 *
 * @param string $maybe_addr Either a username or an email address.
 * @return string The input as an email address.
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
 * @return string The domain of the email address.
 */
function extract_domain( $addr ) {
	$parts = explode( '@', $addr, 2 );
	return $parts[1];
}

/**
 * Get the bounce address that should be used.
 *
 * @param PHPMailer &$mailer The instance of PHPMailer.
 * @return string The bounce address if any.
 */
function get_bounce_address( &$mailer ) {
	$mode = get_option( 'eauth_bounce_address_mode' );

	if ( 'from' === $mode ) {
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		return $mailer->From;
	}

	if ( 'custom' === $mode ) {
		return as_address( get_option( 'eauth_bounce_address' ) );
	}

	return ini_get( 'sendmail_from' ) ?? '';
}

/**
 * Get the DKIM domain that should be used.
 *
 * @param PHPMailer &$mailer The instance of PHPMailer.
 * @return string | null The DKIM domain if any.
 */
function get_dkim_domain( &$mailer ) {
	$mode = get_option( 'eauth_dkim_domain' );

	if ( 'wp' === $mode ) {
		return get_domain();
	}

	if ( 'from' === $mode ) {
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		return extract_domain( $mailer->From );
	}

	if ( 'bounce' === $mode ) {
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		return extract_domain( $mailer->Sender );
	}

	if ( 'custom' === $mode ) {
		return get_option( 'eauth_dkim_domain_custom' );
	}

	return null;
}

add_action(
	'wp_mail_from',
	function ( $from_email ) {
		$force = get_option( 'eauth_from_address_force' );

		if ( ! $force && 'wordpress@' . get_domain() !== $from_email ) {
			return $from_email;
		}

		$addr = get_option( 'eauth_from_address' );
		if ( '' !== $addr ) {
			return as_address( $addr );
		}

		return $from_email;
	},
	PHP_INT_MAX
);

add_action(
	'wp_mail_from_name',
	function ( $from_name ) {
		$force = get_option( 'eauth_from_address_force' );

		if ( ! $force && 'WordPress' !== $from_name ) {
			return $from_name;
		}

		return get_option( 'eauth_from_address_name' ) ?: $from_name;
	},
	PHP_INT_MAX
);

add_action(
	'phpmailer_init',
	function ( &$mailer ) {
		// Add bounce address.
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		$mailer->Sender = get_bounce_address( $mailer );

		// Add reply-to address.
		$reply_to = get_option( 'eauth_reply_to' );
		if ( '' !== $reply_to ) {
			$mailer->addReplyTo( as_address( $reply_to ), get_option( 'eauth_reply_to_name' ) );
		}

		// Add DKIM.
		$selector = get_option( 'eauth_dkim_selector' );
		if ( '' !== $selector ) {
			$keys   = get_keys();
			$domain = get_dkim_domain( $mailer );

			if ( $domain && array_key_exists( $selector, $keys ) ) {
				$key = $keys[ $selector ];

				// phpcs:disable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				$mailer->DKIM_domain         = $domain;
				$mailer->DKIM_private_string = $key;
				$mailer->DKIM_selector       = $selector;
				// phpcs:enable
			}
		}
	},
	PHP_INT_MAX
);
