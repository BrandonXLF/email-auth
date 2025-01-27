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
 */
function add_section( $title, $callback ) {
	global $eauth_sections;

	$eauth_sections[] = [
		'title'    => $title,
		'id'       => str_replace( ' ', '-', strtolower( $title ) ),
		'callback' => $callback,
	];
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
 * @param string | null $placeholder The placeholder text.
 */
function placeholder( $placeholder ) {
	if ( $placeholder ) {
		echo ' placeholder="' . esc_attr( $placeholder ) . '" ';
	}
}

/**
 * Print a placeholder label attribute.
 * 
 * @param string The label text.
 */
function placeholder_label( $label ) {
	echo ' placeholder="' . esc_attr( $label ) . '" aria-label="' . esc_attr( $label ) . '" ';
}

/**
 * Print an email input.
 *
 * @param string        $addr_name The setting name for the email address.
 * @param string | null $addr_placeholder The placeholder for the address.
 * @param string | null $display_name The setting name for the display name.
 * @param string | null $display_placeholder The placeholder for the display name.
 */
function email_input( $addr_name, $addr_placeholder = null, $display_name = null, $display_placeholder = null ) {
	$addr = get_option( $addr_name );
	?>
	<div class="eauth-email-input">
		<div class="eauth-address-input">
			<input name="<?php echo esc_attr( $addr_name ); ?>" value="<?php echo esc_attr( $addr ); ?>" type="text" <?php placeholder( $addr_placeholder ); ?>>
			Default domain: @<?php echo esc_html( get_domain() ); ?>
		</div>
		<div>
			<?php
			if ( $display_name ) {
				$name = get_option( $display_name );
				?>
				Display name:
				<input name="<?php echo esc_attr( $display_name ); ?>" value="<?php echo esc_attr( $name ); ?>" type="text" <?php placeholder( $display_placeholder ); ?>>
			<?php } ?>
		</div>
	</div>
	<?php
}

/**
 * Print radio inputs.
 *
 * @param string                $name The name of the setting.
 * @param array[string]callable $inputs The radio inputs.
 */
function radio_inputs( $name, $inputs ) {
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
	'From Address',
	function () {
		?>
		<div>
			<?php email_input( 'eauth_from_address', 'wordpress@' . get_domain(), 'eauth_from_address_name', 'WordPress' ); ?>
		</div>
		<?php
		$force = get_option( 'eauth_from_address_force' );
		?>
		<div>
			<label>
				<input name="eauth_from_address_force" type="checkbox" value="1" <?php checked( true, $force ); ?>>
				Force the use of the address above and ignore other plugins.
			</label>
		</div>
		<h3>Reply-To Address</h3>
		<div>
			Email address where replies are sent. Leave blank to use the "From" address.
		</div>
		<div>
			<?php email_input( 'eauth_reply_to', null, 'eauth_reply_to_name' ); ?>
		</div>
		<?php
	}
);

add_section(
	'Bounce Address',
	function () {
		$choice = get_option( 'eauth_bounce_address_mode' );
		?>
		<div>
			The bounce address is the address the email as used by SMTP. Think of the bounce address as the address on the envelope and the from address as the address on the top of the letter. It is import for SPF.
		</div>
		<?php
		radio_inputs(
			'eauth_bounce_address_mode',
			[
				''       => function () {
					?>
					<span>Don't set</span>
					<?php
				},
				'from'   => function () {
					?>
					<span>Use the from address<i class="eauth-variable" data-prefix=" - " data-variable="fromAddress"></i></span>
					<?php
				},
				'custom' => function () {
					email_input( 'eauth_bounce_address' );
				},
			]
		);
	}
);

add_section(
	'DKIM',
	function () {
		$selector = get_option( 'eauth_dkim_selector' );

		wp_enqueue_script(
			'eauth_dkim_script',
			plugin_dir_url( EAUTH_PLUGIN_FILE ) . 'admin/js/dkim.js',
			[ 'jquery', 'eauth_common' ],
			EAUTH_PLUGIN_VERSION,
			[ 'in_footer' => true ]
		);

		wp_localize_script(
			'eauth_dkim_script',
			'eauthDkimApi',
			[ 'keys' => esc_url_raw( rest_url( 'eauth/v1/dkim/keys' ) ) ]
		);
		?>
		<div id="eauth-dkim-status" class="eauth-status"></div>
		<div class="eauth-pre-output-static">
			<label>
				Selector:
				<select name="eauth_dkim_selector">
					<option value="">Disabled</option>
					<option selected><?php echo esc_html( $selector ); ?></option>
				</select>
			</label>
		</div>
		<div id="eauth-dkim-dns" class="eauth-output"></div>
		<h3>Manage Keys</h3>
		<div id="eauth-dkim-manager-error" class="error inline multiline"></div>
		<ul id="eauth-dkim-manager"></ul>
		<div>
			<input name="eauth_dkim_new_selector" id="dkim-new-name" type="text" <?php placeholder_label('Selector name'); ?>>
			<button type="button" id="eauth-dkim-upload" class="button">Upload Key</button>
			<button type="button" id="eauth-dkim-create" class="button">Create Key</button>
		</div>
		<h3 id="dkim-domain">DKIM Domain</h3>
		<div>
			The DKIM domain is the domain that is verified through the DKIM check. If it does not match the "From" address, then the email may be rejected or displayed differently.
		</div>
		<?php
		radio_inputs(
			'eauth_dkim_domain',
			[
				'wp'     => function () {
					?>
					<span>Use WordPress's domain - <span class="eauth-value"><?php echo esc_html( get_domain() ); ?></span></span>
					<?php
				},
				'from'   => function () {
					?>
					<span>Use the from address's domain<span class="eauth-variable" data-prefix=" - " data-variable="fromDomain"></span></span>
					<?php
				},
				'bounce' => function () {
					?>
					<span>Use the bounce address's domain<span class="eauth-variable" data-prefix=" - " data-variable="bounceDomain"></span></span>
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
	}
);

add_section(
	'SPF',
	function () {
		wp_enqueue_script(
			'eauth_spf_script',
			plugin_dir_url( EAUTH_PLUGIN_FILE ) . 'admin/js/spf.js',
			[ 'jquery', 'eauth_common' ],
			EAUTH_PLUGIN_VERSION,
			[ 'in_footer' => true ]
		);

		wp_localize_script(
			'eauth_spf_script',
			'eauthSpfApi',
			[ 'check' => esc_url_raw( rest_url( 'eauth/v1/spf/check' ) ) ]
		);
		?>
		<div id="eauth-spf-status" class="eauth-status"></div>
		<div id="eauth-spf-checker" class="eauth-output"></div>
		<?php
	}
);

add_section(
	'DMARC',
	function () {
		wp_enqueue_script(
			'eauth_dmarc_script',
			plugin_dir_url( EAUTH_PLUGIN_FILE ) . 'admin/js/dmarc.js',
			[ 'jquery', 'eauth_common' ],
			EAUTH_PLUGIN_VERSION,
			[ 'in_footer' => true ]
		);

		wp_localize_script(
			'eauth_spf_script',
			'eauthDmarcApi',
			[ 'check' => esc_url_raw( rest_url( 'eauth/v1/dmarc/check' ) ) ]
		);
		?>
		<div id="eauth-dmarc-status" class="eauth-status"></div>
		<div id="eauth-dmarc-checker" class="eauth-output"></div>
		<?php
	}
);

add_section(
	'Save Changes',
	function () {
		?>
		<div>
			<input id="eauth-test-to" name="eauth_test_to" type="email" <?php placeholder_label('Test email address'); ?>>
			<input type="submit" name="eauth_send_test" value="Save & Send Test" class="button">
		</div>
		<div>
			<input type="submit" value="<?php echo esc_attr( 'Save Changes' ); ?>" class="button button-primary">
		</div>
		<?php
	}
);
