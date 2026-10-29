<?php
/**
 * Setting sections.
 *
 * @package Email Auth
 */

namespace EmailAuthPlugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$eauth_sections = [];

/**
 * Register a settings section.
 *
 * @param string   $title The title.
 * @param callable $callback A callback the generates the section's content.
 * @param string   $id Optional stable section id for in-page links (defaults from English slug).
 */
function add_section( $title, $callback, $id = null ) {
	global $eauth_sections;

	if ( null === $id ) {
		$id = str_replace( ' ', '-', strtolower( $title ) );
	}

	$eauth_sections[] = [
		'title'    => $title,
		'id'       => $id,
		'callback' => $callback,
	];
}

/**
 * Enqueue an admin script and load script translations.
 *
 * @param string $handle Script handle.
 * @param string $file Path under the plugin root, e.g. admin/js/spf.js.
 */
function enqueue_admin_script( $handle, $file ) {
	wp_enqueue_script(
		$handle,
		plugin_dir_url( EAUTH_PLUGIN_FILE ) . $file,
		[ 'jquery', 'eauth_common' ],
		EAUTH_PLUGIN_VERSION,
		[ 'in_footer' => true ]
	);

	wp_set_script_translations( $handle, 'email-auth' );
}

/**
 * Show a list of links to all the sections.
 */
function show_toc() {
	global $eauth_sections;

	echo '<div id="eauth-toc"><ul>';

	foreach ( $eauth_sections as $section ) {
		$id    = $section['id'];
		$title = $section['title'];
		echo '<li><a href="' . esc_url( '#' . $id ) . '">' . esc_html( $title ) . '</a></li>';
	}

	echo '</ul></div>';
}

/**
 * Show all the sections.
 */
function show_sections() {
	global $eauth_sections;

	foreach ( $eauth_sections as $section ) {
		$id = $section['id'];

		echo '<h2 id="' . esc_attr( $id ) . '">' . esc_html( $section['title'] ) . '</h2>';
		call_user_func( $section['callback'] );
	}
}

/**
 * Print a possibly-defined placeholder attribute.
 *
 * @param string|null $placeholder The placeholder text.
 */
function placeholder( $placeholder ) {
	if ( $placeholder ) {
		echo ' placeholder="' . esc_attr( $placeholder ) . '" ';
	}
}

/**
 * Print a placeholder label attribute.
 *
 * @param string $label The label text.
 */
function placeholder_label( $label ) {
	echo ' placeholder="' . esc_attr( $label ) . '" aria-label="' . esc_attr( $label ) . '" ';
}

/**
 * Print an email input.
 *
 * @param string      $addr_name The setting name for the email address.
 * @param string|null $addr_placeholder The placeholder for the address.
 * @param string|null $display_name The setting name for the display name.
 * @param string|null $display_placeholder The placeholder for the display name.
 */
function email_input( $addr_name, $addr_placeholder = null, $display_name = null, $display_placeholder = null ) {
	$addr = get_option( $addr_name );
	?>
	<div class="eauth-email-input">
		<div class="eauth-address-input">
			<input name="<?php echo esc_attr( $addr_name ); ?>" value="<?php echo esc_attr( $addr ); ?>" type="text" <?php placeholder( $addr_placeholder ); ?>>
			<?php
			printf(
				/* translators: %s: default email domain hostname */
				\esc_html__( 'Default domain: @%s', 'email-auth' ),
				esc_html( get_domain() )
			);
			?>
		</div>
		<div>
			<?php
			if ( $display_name ) {
				$name = get_option( $display_name );
				?>
				<?php \esc_html_e( 'Display name:', 'email-auth' ); ?>
				<input name="<?php echo esc_attr( $display_name ); ?>" value="<?php echo esc_attr( $name ); ?>" type="text" <?php placeholder( $display_placeholder ); ?>>
			<?php } ?>
		</div>
	</div>
	<?php
}

/**
 * Print radio inputs.
 *
 * @param string                          $name   The name of the setting.
 * @param array<string, callable(): void> $inputs Map of stored value to label markup callback.
 */
function radio_inputs( string $name, array $inputs ) {
	$choice = get_option( $name );
	?>
	<div class="eauth-radio-options">
		<?php
		foreach ( $inputs as $value => $callback ) {
			?>
			<div>
				<label>
					<input type="radio" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( $value ); ?>" <?php checked( $value, $choice ); ?>>
					<?php call_user_func( $callback ); ?>
				</label>
			</div>
			<?php
		}
		?>
	</div>
	<?php
}

add_section(
	\__( 'From Address', 'email-auth' ),
	function () {
		?>
		<div>
			<?php
			email_input(
				'eauth_from_address',
				'wordpress@' . get_domain(),
				'eauth_from_address_name',
				\__( 'WordPress', 'email-auth' )
			);
			?>
		</div>
		<?php
		$force = get_option( 'eauth_from_address_force' );
		?>
		<div>
			<label>
				<input name="eauth_from_address_force" type="checkbox" value="1" <?php checked( true, $force ); ?>>
				<?php \esc_html_e( 'Force the use of the address above and ignore other plugins.', 'email-auth' ); ?>
			</label>
		</div>
		<h3><?php \esc_html_e( 'Reply-To Address', 'email-auth' ); ?></h3>
		<div>
			<?php \esc_html_e( 'Email address where replies are sent. Leave blank to use the "From" address.', 'email-auth' ); ?>
		</div>
		<div>
			<?php email_input( 'eauth_reply_to', null, 'eauth_reply_to_name' ); ?>
		</div>
		<?php
	},
	'from-address'
);

add_section(
	\__( 'Bounce Address', 'email-auth' ),
	function () {
		?>
		<div>
			<?php \esc_html_e( 'The bounce address is the address of the email as used by SMTP. It\'s not typically seen by users, but it\'s important for SPF. Think of the bounce address as the address on the envelope and the from address as the address on the top of the letter.', 'email-auth' ); ?>
		</div>
		<?php
		radio_inputs(
			'eauth_bounce_address_mode',
			[
				''       => function () {
					?>
					<span><?php \esc_html_e( 'Don\'t set', 'email-auth' ); ?></span>
					<?php
				},
				'from'   => function () {
					?>
					<span><?php \esc_html_e( 'Use the from address', 'email-auth' ); ?><i class="eauth-variable" data-prefix=" - " data-variable="fromAddress"></i></span>
					<?php
				},
				'custom' => function () {
					email_input( 'eauth_bounce_address' );
				},
			]
		);
	},
	'bounce-address'
);

add_section(
	\__( 'DKIM', 'email-auth' ),
	function () {
		$selector = get_option( 'eauth_dkim_selector' );

		enqueue_admin_script( 'eauth_dkim_script', 'admin/js/dkim.js' );

		wp_localize_script(
			'eauth_dkim_script',
			'eauthDkimApi',
			[ 'keys' => esc_url_raw( rest_url( 'eauth/v1/dkim/keys' ) ) ]
		);
		?>
		<div id="eauth-dkim-status" class="eauth-status"></div>
		<div class="eauth-pre-output-static">
			<label>
				<?php \esc_html_e( 'Selector:', 'email-auth' ); ?>
				<select name="eauth_dkim_selector">
					<option value=""><?php \esc_html_e( 'Disabled', 'email-auth' ); ?></option>
					<option selected><?php echo esc_html( $selector ); ?></option>
				</select>
			</label>
		</div>
		<div id="eauth-dkim-dns" class="eauth-output"></div>
		<h3><?php \esc_html_e( 'Manage Keys', 'email-auth' ); ?></h3>
		<div id="eauth-dkim-manager-error" class="error inline multiline"></div>
		<ul id="eauth-dkim-manager"></ul>
		<div>
			<input name="eauth_dkim_new_selector" id="dkim-new-name" type="text" <?php placeholder_label( \__( 'Selector name', 'email-auth' ) ); ?>>
			<button type="button" id="eauth-dkim-upload" class="button"><?php \esc_html_e( 'Upload Key', 'email-auth' ); ?></button>
			<button type="button" id="eauth-dkim-create" class="button"><?php \esc_html_e( 'Create Key', 'email-auth' ); ?></button>
		</div>
		<h3 id="dkim-domain"><?php \esc_html_e( 'DKIM Domain', 'email-auth' ); ?></h3>
		<div>
			<?php \esc_html_e( 'The DKIM domain is the domain that is verified through the DKIM check. If it does not match the "From" address, then the email may be rejected or displayed differently.', 'email-auth' ); ?>
		</div>
		<?php
		radio_inputs(
			'eauth_dkim_domain',
			[
				'wp'     => function () {
					?>
					<span>
						<?php \esc_html_e( 'Use WordPress\'s domain -', 'email-auth' ); ?>
						<span class="eauth-value"><?php echo esc_html( get_domain() ); ?></span>
					</span>
					<?php
				},
				'from'   => function () {
					?>
					<span><?php \esc_html_e( 'Use the from address\'s domain', 'email-auth' ); ?><span class="eauth-variable" data-prefix=" - " data-variable="fromDomain"></span></span>
					<?php
				},
				'bounce' => function () {
					?>
					<span><?php \esc_html_e( 'Use the bounce address\'s domain', 'email-auth' ); ?><span class="eauth-variable" data-prefix=" - " data-variable="bounceDomain"></span></span>
					<?php
				},
				'custom' => function () {
					$custom = get_option( 'eauth_dkim_domain_custom' );
					?>
					<input name="eauth_dkim_domain_custom" value="<?php echo esc_attr( $custom ); ?>" type="text">
					<?php
				},
			]
		);
	},
	'dkim'
);

add_section(
	\__( 'SPF', 'email-auth' ),
	function () {
		enqueue_admin_script( 'eauth_spf_script', 'admin/js/spf.js' );

		wp_localize_script(
			'eauth_spf_script',
			'eauthSpfApi',
			[
				'check' => esc_url_raw( rest_url( 'eauth/v1/spf/check' ) ),
				'setIp' => esc_url_raw( rest_url( 'eauth/v1/spf/set-ip' ) ),
			],
		);
		?>
		<div id="eauth-spf-status" class="eauth-status"></div>
		<div id="eauth-spf-checker" class="eauth-output"></div>
		<dialog id="eauth-spf-set-ip-dialog" class="eauth-dialog">
			<h3><?php \esc_html_e( 'Email Server IP Address for SPF Checks', 'email-auth' ); ?></h3>
			<p>
				<?php \esc_html_e( 'To get accurate SPF checks, this must be the IP address of the server that sends outbound emails.', 'email-auth' ); ?>
			</p>
			<?php
			radio_inputs(
				'eauth_spf_server_ip',
				[
					'wp'     => function () {
						?>
						<span>
							<?php \esc_html_e( 'Use WordPress\'s server\'s IP address - Emails are sent from the same server as WordPress', 'email-auth' ); ?>
						</span>
						<?php
					},
					'bounce' => function () {
						?>
						<span>
							<?php \esc_html_e( 'Use the bounce address\'s mail exchange IP - Same server is used for inbound and outbound emails', 'email-auth' ); ?>
						</span>
						<?php
					},
					'custom' => function () {
						$custom = get_option( 'eauth_spf_server_ip_custom' );
						?>
						<input name="eauth_spf_server_ip_custom" value="<?php echo esc_attr( $custom ); ?>" type="text">
						<a target="_blank" href="https://www.youtube.com/watch?v=_QNxGwEFTS4"><?php \esc_html_e( 'Guide video', 'email-auth' ); ?></a>
						<?php
					},
				]
			);
		?>
			<div id="eauth-spf-set-ip-buttons">
				<button type="button" id="eauth-spf-set-ip" class="button">
					<?php \esc_html_e( 'Save IP Configuration', 'email-auth' ); ?>
				</button>
				<button type="button" id="eauth-spf-set-ip-close" class="button-link">
					<?php \esc_html_e( 'Close', 'email-auth' ); ?>
				</button>
			</div>
		</dialog>
		<?php
	},
	'spf'
);

add_section(
	\__( 'DMARC', 'email-auth' ),
	function () {
		enqueue_admin_script( 'eauth_dmarc_script', 'admin/js/dmarc.js' );

		wp_localize_script(
			'eauth_spf_script',
			'eauthDmarcApi',
			[
				'check' => esc_url_raw( rest_url( 'eauth/v1/dmarc/check' ) ),
				'org'   => esc_url_raw( rest_url( 'eauth/v1/dmarc/org-domain' ) ),
			]
		);
		?>
		<div id="eauth-dmarc-status" class="eauth-status"></div>
		<div id="eauth-dmarc-checker" class="eauth-output"></div>
		<?php
	},
	'dmarc'
);

add_section(
	\__( 'Save Changes', 'email-auth' ),
	function () {
		?>
		<div>
			<input id="eauth-test-to" name="eauth_test_to" type="email" <?php placeholder_label( \__( 'Test email address', 'email-auth' ) ); ?>>
			<input type="submit" name="eauth_send_test" value="<?php echo \esc_attr__( 'Save & Send Test', 'email-auth' ); ?>" class="button">
		</div>
		<div>
			<input type="submit" value="<?php echo \esc_attr__( 'Save Changes', 'email-auth' ); ?>" class="button button-primary">
		</div>
		<?php
	},
	'save-changes'
);
