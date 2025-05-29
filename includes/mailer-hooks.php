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

add_action(
	'wp_mail_from',
	function ( $from_email ) {
		$force = get_option( 'eauth_from_address_force' );

		if ( ! $force && 'wordpress@' . get_domain() !== $from_email ) {
			return $from_email;
		}

		return get_from_address() ?: $from_email;
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
		$mailer->Sender = get_bounce_address( $mailer->From );

		// Add reply-to address.
		$reply_to = get_option( 'eauth_reply_to' );
		if ( '' !== $reply_to ) {
			$mailer->addReplyTo( as_address( $reply_to ), get_option( 'eauth_reply_to_name' ) );
		}

		// Add DKIM.
		$selector = get_option( 'eauth_dkim_selector' );
		if ( '' !== $selector ) {
			$keys = get_keys();
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			$domain = get_dkim_domain( $mailer->From, $mailer->Sender );

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
