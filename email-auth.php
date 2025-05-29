<?php
/**
 * Email Auth
 *
 * @package           Email Auth
 * @author            Brandon Fowler
 * @copyright         Brandon Fowler
 * @license           GPL-2.0+
 *
 * @wordpress-plugin
 * Plugin Name:       Email Auth
 * Plugin URI:        https://www.brandonfowler.me/email-auth/
 * Description:       Enable email authentication/validation for the default WordPress PHPMailer.
 * Version:           1.4.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Brandon Fowler
 * Author URI:        https://www.brandonfowler.me/wordpress-plugins/
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 */

namespace EmailAuthPlugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'EAUTH_PLUGIN_FILE', __FILE__ );
define( 'EAUTH_PLUGIN_VERSION', '1.4.0' );

require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/includes/utils/common.php';
require __DIR__ . '/includes/utils/get-settings.php';

require __DIR__ . '/includes/mailer-hooks.php';
require __DIR__ . '/includes/admin-interface.php';

add_action(
	'init',
	function () {
		require __DIR__ . '/includes/settings.php';
	}
);
