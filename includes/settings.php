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
	[
		'default'           => '',
		'type'              => 'string',
		'sanitize_callback' => 'sanitize_email',
	]
);

register_setting(
	'eauth_settings',
	'eauth_from_address_name',
	[
		'default'           => '',
		'type'              => 'string',
		'sanitize_callback' => 'sanitize_text_field',
	]
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
	[
		'default'           => '',
		'type'              => 'string',
		'sanitize_callback' => 'sanitize_email',
	]
);

register_setting(
	'eauth_settings',
	'eauth_reply_to_name',
	[
		'default'           => '',
		'type'              => 'string',
		'sanitize_callback' => 'sanitize_text_field',
	]
);

register_setting(
	'eauth_settings',
	'eauth_bounce_address_mode',
	[
		'default'           => 'from',
		'type'              => 'string',
		'sanitize_callback' => 'sanitize_text_field',
	]
);

register_setting(
	'eauth_settings',
	'eauth_bounce_address',
	[
		'default'           => '',
		'type'              => 'string',
		'sanitize_callback' => 'sanitize_email',
	]
);

register_setting(
	'eauth_settings',
	'eauth_dkim_selector',
	[
		'default'           => '',
		'type'              => 'string',
		'sanitize_callback' => 'sanitize_text_field',
	]
);

register_setting(
	'eauth_settings',
	'eauth_dkim_domain',
	[
		'default'           => 'from',
		'type'              => 'string',
		'sanitize_callback' => 'sanitize_text_field',
	]
);

register_setting(
	'eauth_settings',
	'eauth_dkim_domain_custom',
	[
		'default'           => '',
		'type'              => 'string',
		'sanitize_callback' => 'sanitize_text_field',
	]
);
