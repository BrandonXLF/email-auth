<?php
/**
 * Hooks for the admin interface.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action(
	'admin_enqueue_scripts',
	function () {
		wp_register_script(
			'eauth_common',
			plugin_dir_url( EAUTH_PLUGIN_FILE ) . 'admin/js/common.js',
			[ 'jquery' ],
			EAUTH_PLUGIN_VERSION,
			[ 'in_footer' => true ]
		);

		wp_localize_script(
			'eauth_common',
			'eauthCommonConfig',
			[
				'domain' => get_domain(),
				'nonce'  => wp_create_nonce( 'wp_rest' ),
			]
		);
	}
);

add_action(
	'admin_menu',
	function () {
		add_options_page(
			'Configure Email Authentication',
			'Email Auth',
			'manage_options',
			'email-auth',
			function () {
				require __DIR__ . '/setting-sections.php';
				require __DIR__ . '/menu-page.php';
			},
			1
		);
	}
);

add_action(
	'rest_api_init',
	function () {
		require __DIR__ . '/api-routes.php';
	}
);

/**
 * Add an error associated with test email sending.
 *
 * @param array[array] &$errors The arary of errors.
 * @param string       $type The type of the error.
 * @param string       $message The error message.
 */
function add_email_error( &$errors, $type, $message ) {
	$errors[] = [
		'settings' => 'general',
		'code'     => 'eauth_test_email_result',
		'message'  => $message,
		'type'     => $type,
	];
}

// Fired after options are processed but before options.php exits.
add_action(
	'pre_set_transient_settings_errors',
	function ( $value ) {
		// Set internally by WordPress.
		global $option_page;

		// We are being called from options.php (sets $option_page) after nonce has been verified.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( isset( $option_page ) && 'eauth_settings' === $option_page && ! empty( $_REQUEST['eauth_send_test'] ) ) {
			if ( empty( $_REQUEST['eauth_test_to'] ) ) {
				add_email_error( $value, 'error', 'No email address given.' );
				return $value;
			}

			$success = wp_mail(
				sanitize_email( wp_unslash( $_REQUEST['eauth_test_to'] ) ),
				'Email Auth Test',
				'This is a test email from the Email Auth WordPress plugin.'
			);

			if ( ! $success ) {
				add_email_error( $value, 'error', 'Test email failed.' );
			} else {
				add_email_error( $value, 'success', 'Test email sent.' );
			}

			return $value;
		}
		// phpcs:enable
	}
);
