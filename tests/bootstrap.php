<?php
/**
 * PHPUnit bootstrap file.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
$_tests_dir = getenv( 'WP_TESTS_DIR' );

if ( ! $_tests_dir ) {
	$_tests_dir = rtrim( sys_get_temp_dir(), '/\\' ) . '/wordpress-tests-lib';
}
// phpcs:enable

if ( ! file_exists( "{$_tests_dir}/includes/functions.php" ) ) {
	echo 'Ignore if running unit tests only:' . PHP_EOL;

	// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	echo "Could not find {$_tests_dir}/includes/functions.php, have you run bin/install-wp-tests.sh ?" . PHP_EOL;

	// Needed to let plugin files execute.
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
	define( 'ABSPATH', true );

	require dirname( __DIR__ ) . '/vendor/autoload.php';
	require dirname( __DIR__ ) . '/includes/utils/common.php';
} else {
	// Give access to tests_add_filter() function.
	require_once "{$_tests_dir}/includes/functions.php";

	// Manually load the plugin.
	tests_add_filter(
		'muplugins_loaded',
		function () {
			require dirname( __DIR__ ) . '/email-auth.php';
		}
	);

	// Start up the WP testing environment.
	require "{$_tests_dir}/includes/bootstrap.php";
}

require __DIR__ . '/polyfill.php';
