<?php
/**
 * The options page the Email Auth plugin.
 *
 * @package Email Auth.
 */

namespace EmailAuthPlugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

wp_enqueue_style(
	'eauth_common_css',
	plugin_dir_url( EAUTH_PLUGIN_FILE ) . 'admin/css/common.css',
	[],
	EAUTH_PLUGIN_VERSION
);

?>

<div class="wrap" id="eauth-wrap">
	<h1>Email Auth</h1>
	<form action="options.php" method="post" id="eauth-options">
		<?php settings_fields( 'eauth_settings' ); ?>
		<?php show_toc(); ?>
		<?php show_sections(); ?>
	</form>
</div>

