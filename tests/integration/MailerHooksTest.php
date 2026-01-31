<?php
/**
 * Tests for mailer-hooks.php
 *
 * @package Email Auth
 */

// phpcs:disable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase

namespace EmailAuthPlugin;

/**
 * Tests for check_dkim_dns.
 */
class MailerHooksTest extends \WP_UnitTestCase {
	public function set_up(): void {
		parent::set_up();
		reset_phpmailer_instance();
	}

	public function testNoneSet() {
		global $phpmailer;

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$this->assertEquals( 'wordpress@example.org', $phpmailer->From );
		$this->assertEquals( 'WordPress', $phpmailer->FromName );

		$this->assertEquals( 'wordpress@example.org', actual: $phpmailer->Sender );
		$this->assertEquals( [], $phpmailer->getReplyToAddresses() );

		$this->assertEmpty( $phpmailer->DKIM_domain );
		$this->assertEmpty( $phpmailer->DKIM_private_string );
		$this->assertEmpty( $phpmailer->DKIM_selector );

		$this->assertCount( 1, $phpmailer->mock_sent );
	}

	public function testBlankableBlank() {
		global $phpmailer;

		// Bounce address is the only blankable not set as blank by default.
		update_option( 'eauth_bounce_address_mode', '' );

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$this->assertEquals( '', $phpmailer->Sender );

		delete_option( 'eauth_bounce_address_mode' );
	}

	public function testFromAddress() {
		global $phpmailer;

		update_option( 'eauth_from_address', 'hello@domain.test' );

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$this->assertEquals( 'hello@domain.test', $phpmailer->From );
		$this->assertEquals( 'WordPress', $phpmailer->FromName );
		$this->assertEquals( 'hello@domain.test', $phpmailer->Sender );

		delete_option( 'eauth_from_address' );
	}

	public function testFromName() {
		global $phpmailer;

		update_option( 'eauth_from_address_name', 'Hello' );

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$this->assertEquals( 'Hello', $phpmailer->FromName );

		delete_option( 'eauth_from_address_name' );
	}

	public function testNoOverride() {
		global $phpmailer;

		update_option( 'eauth_from_address', 'hello@domain.test' );
		update_option( 'eauth_from_address_name', 'Hello' );

		$other_plugin_from = function () {
			return 'help@plugin.test';
		};
		$other_plugin_name = function () {
			return 'Help Desk';
		};

		add_action( 'wp_mail_from', $other_plugin_from );
		add_action( 'wp_mail_from_name', $other_plugin_name );

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$this->assertEquals( 'help@plugin.test', $phpmailer->From );
		$this->assertEquals( 'Help Desk', $phpmailer->FromName );
		$this->assertEquals( 'help@plugin.test', $phpmailer->Sender );

		remove_action( 'wp_mail_from', $other_plugin_from );
		remove_action( 'wp_mail_from', $other_plugin_name );

		delete_option( 'eauth_from_address' );
		delete_option( 'eauth_from_address_name' );
	}

	public function testOverride() {
		global $phpmailer;

		update_option( 'eauth_from_address', 'hello@domain.test' );
		update_option( 'eauth_from_address_name', 'Hello' );
		update_option( 'eauth_from_address_force', '1' );

		$other_plugin_from = function () {
			return 'help@plugin.test';
		};
		$other_plugin_name = function () {
			return 'Help Desk';
		};

		add_action( 'wp_mail_from', $other_plugin_from );
		add_action( 'wp_mail_from_name', $other_plugin_name );

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$this->assertEquals( 'hello@domain.test', $phpmailer->From );
		$this->assertEquals( 'Hello', $phpmailer->FromName );
		$this->assertEquals( 'hello@domain.test', $phpmailer->Sender );

		remove_action( 'wp_mail_from', $other_plugin_from );
		remove_action( 'wp_mail_from', $other_plugin_name );

		delete_option( 'eauth_from_address' );
		delete_option( 'eauth_from_address_name' );
		delete_option( 'eauth_from_address_force' );
	}

	public function testReplyToEmailOnly() {
		global $phpmailer;

		update_option( 'eauth_reply_to', 'me@reply.test' );

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$phpmailer_addresses = $phpmailer->getReplyToAddresses();
		$this->assertCount( 1, $phpmailer_addresses );
		$this->assertEquals(
			[ 'me@reply.test', '' ],
			reset( $phpmailer_addresses )
		);

		delete_option( 'eauth_reply_to' );
	}

	public function testReplyTo() {
		global $phpmailer;

		update_option( 'eauth_reply_to', 'me@reply.test' );
		update_option( 'eauth_reply_to_name', 'My Inbox' );

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$phpmailer_addresses = $phpmailer->getReplyToAddresses();
		$this->assertCount( 1, $phpmailer_addresses );
		$this->assertEquals(
			[ 'me@reply.test', 'My Inbox' ],
			reset( $phpmailer_addresses )
		);

		delete_option( 'eauth_reply_to' );
		delete_option( 'eauth_reply_to_name' );
	}


	public function testIgnoreUnusedBounceAddress() {
		global $phpmailer;

		update_option( 'eauth_bounce_address', 'bounce@testing.test' );

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$this->assertEquals( 'wordpress@example.org', $phpmailer->Sender );

		delete_option( 'eauth_bounce_address' );
	}

	public function testCustomBounceAddress() {
		global $phpmailer;

		update_option( 'eauth_bounce_address_mode', 'custom' );
		update_option( 'eauth_bounce_address', 'bounce@testing.test' );

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$this->assertEquals( 'bounce@testing.test', $phpmailer->Sender );

		delete_option( 'eauth_bounce_address_mode' );
		delete_option( 'eauth_bounce_address' );
	}

	public function testDkim() {
		global $phpmailer;

		save_keys( [ 'test' => file_get_contents( dirname( __DIR__ ) . '/test.pem' ) ] );

		update_option( 'eauth_dkim_selector', 'test' );

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$this->assertEquals( 'example.org', $phpmailer->DKIM_domain );
		$this->assertEquals( file_get_contents( dirname( __DIR__ ) . '/test.pem' ), $phpmailer->DKIM_private_string );
		$this->assertEquals( 'test', $phpmailer->DKIM_selector );

		delete_option( 'eauth_dkim_selector' );
	}

	public function dkimModeProvider() {
		return [
			[ 'wp', 'example.org' ],
			[ 'from', 'from.test' ],
			[ 'bounce', 'bounce.test' ],
			[ 'custom', 'custom.test' ],
		];
	}

	/**
	 * Test different DKIM domain modes.
	 *
	 * @dataProvider dkimModeProvider
	 *
	 * @param string $mode The DKIM domain mode being tested.
	 * @param string $expected The expected value of the DKIM domain.
	 */
	public function testDkimDomainMode( $mode, $expected ) {
		global $phpmailer;

		save_keys( [ 'test' => file_get_contents( dirname( __DIR__ ) . '/test.pem' ) ] );

		update_option( 'eauth_dkim_selector', 'test' );
		update_option( 'eauth_dkim_domain', $mode );
		update_option( 'eauth_from_address', 'dkim@from.test' );
		update_option( 'eauth_bounce_address_mode', 'custom' );
		update_option( 'eauth_bounce_address', 'dkim@bounce.test' );
		update_option( 'eauth_dkim_domain_custom', 'custom.test' );

		wp_mail( 'test@domain.test', 'Test', 'Testing 1 2 3' );

		$this->assertEquals( $expected, $phpmailer->DKIM_domain );

		delete_option( 'eauth_dkim_selector' );
		delete_option( 'eauth_dkim_domain' );
		delete_option( 'eauth_from_address' );
		delete_option( 'eauth_bounce_address_mode' );
		delete_option( 'eauth_bounce_address' );
		delete_option( 'eauth_dkim_domain_custom' );
	}
}
