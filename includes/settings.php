<?php
/**
 * Settings used by the  Email Auth plugin.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

register_setting(
	'eauth_settings',
	'eauth_from_address',
	[ 'default' => '' ]
);

register_setting(
	'eauth_settings',
	'eauth_from_address_name',
	[ 'default' => '' ]
);

register_setting(
	'eauth_settings',
	'eauth_from_address_force',
	[
		'default'           => '',
		'type'              => 'boolean',
		'sanitize_callback' => 'boolval',
	]
);

register_setting(
	'eauth_settings',
	'eauth_reply_to',
	[ 'default' => '' ]
);

register_setting(
	'eauth_settings',
	'eauth_reply_to_name',
	[ 'default' => '' ]
);

register_setting(
	'eauth_settings',
	'eauth_bounce_address_mode',
	[ 'default' => 'from' ]
);

register_setting(
	'eauth_settings',
	'eauth_bounce_address',
	[ 'default' => '' ]
);

register_setting(
	'eauth_settings',
	'eauth_dkim_selector',
	[ 'default' => '' ]
);

register_setting(
	'eauth_settings',
	'eauth_dkim_domain',
	[ 'default' => 'from' ]
);

register_setting(
	'eauth_settings',
	'eauth_dkim_domain_custom',
	[ 'default' => '' ]
);
