<?php
/**
 * Uninstall script.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
// phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query( "DELETE FROM $wpdb->options WHERE option_name LIKE 'eauth_%'" );
// phpcs:enable

wp_delete_file( ABSPATH . '/eauth-keys.php' );

wp_cache_flush();
