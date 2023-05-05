<?php // phpcs:ignore - WordPress.Files.FileName.InvalidClassFileName

namespace Automattic\Jetpack\Waf\Brute_Force_Protection;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Redirect;
use Jetpack_Options;
use WP_Error;

/**
 * Class Brute_Force_Protection_Blocked_Login_Page
 *
 * Instanciated on the wp-login page when Jetpack modules are loaded and $pagenow
 * is available, or during the login_head hook.
 *
 * Class will only be instanciated if Brute Force Protection has detected a hard blocked IP address.
 */
class Brute_Force_Protection_Blocked_Login_Page {

	/**
	 * Instance of the class.
	 *
	 * @var Brute_Force_Protection_Blocked_Login_Page
	 */
	private static $instance = null;

	/**
	 * Can send recovery emails. defaults to true.
	 *
	 * @var bool
	 */
	public $can_send_recovery_emails;

	/**
	 * The IP address.
	 *
	 * @var string
	 */
	public $ip_address;

	/**
	 * Valid blocked user ID.
	 *
	 * @var int
	 */
	public $valid_blocked_user_id;

	/**
	 * The email address.
	 *
	 * @var string
	 */
	public $email_address;

	/**
	 * Status code for too many requests.
	 *
	 * @var int
	 */
	const HTTP_STATUS_CODE_TOO_MANY_REQUESTS = 429;

	/**
	 * Singleton implementation
	 *
	 * @param string $ip_address - the IP address.
	 *
	 * @return object
	 */
	public static function instance( $ip_address ) {
		if ( ! is_a( self::$instance, 'Brute_Force_Protection_Blocked_Login_Page' ) ) {
			self::$instance = new Brute_Force_Protection_Blocked_Login_Page( $ip_address );
		}

		return self::$instance;
	}

	/**
	 * Singleton implementation
	 *
	 * @param string $ip_address - the IP address.
	 */
	public function __construct( $ip_address ) {

		/**
		 * Filter controls if an email recovery form is shown to blocked IPs.
		 *
		 * A recovery form allows folks to re-gain access to the login form
		 * via an email link if their IP was mistakenly blocked.
		 *
		 * @module protect
		 *
		 * @since 5.6.0
		 *
		 * @param bool $can_send_recovery_emails Defaults to true.
		 */
		$this->can_send_recovery_emails = apply_filters( 'jetpack_protect_can_send_recovery_emails', true );
		$this->ip_address               = $ip_address;

		add_filter( 'wp_authenticate_user', array( $this, 'check_valid_blocked_user' ), 10, 1 );
		add_filter( 'site_url', array( $this, 'add_args_to_login_post_url' ), 10, 3 );
		add_filter( 'network_site_url', array( $this, 'add_args_to_login_post_url' ), 10, 3 );
		add_filter( 'lostpassword_url', array( $this, 'add_args_to_lostpassword_url' ), 10, 2 );
		add_filter( 'login_url', array( $this, 'add_args_to_login_url' ), 10, 3 );
		add_filter( 'lostpassword_redirect', array( $this, 'add_args_to_lostpassword_redirect_url' ), 10, 1 );
	}

	/**
	 * Gets the URL that redirects to the support page on unblocking
	 *
	 * @since 8.5.0
	 *
	 * @return string
	 */
	public static function get_help_url() {
		return Redirect::get_url( 'jetpack-support-protect', array( 'anchor' => 'troubleshooting' ) );
	}

	/**
	 * Add arguments to lost password redirect url.
	 *
	 * @param string $url - the URL.
	 */
	public function add_args_to_lostpassword_redirect_url( $url ) {
		if ( $this->valid_blocked_user_id ) {
			$url = empty( $url ) ? wp_login_url() : $url;
			$url = add_query_arg(
				array(
					'validate_jetpack_protect_recovery' => isset( $_GET['validate_jetpack_protect_recovery'] ) ? filter_var( wp_unslash( $_GET['validate_jetpack_protect_recovery'] ) ) : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nothing on the site is changed in response to this request.
					'user_id'                           => isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nothing on the site is changed in response to this request.
					'checkemail'                        => 'confirm',
				),
				$url
			);
		}

		return $url;
	}

	/**
	 * Add arguments to lost password redirect url.
	 *
	 * @param string $url - the URL.
	 * @param string $redirect - where to redirect to.
	 */
	public function add_args_to_lostpassword_url( $url, $redirect ) {
		if ( $this->valid_blocked_user_id ) {
			$args = array(
				'validate_jetpack_protect_recovery' => isset( $_GET['validate_jetpack_protect_recovery'] ) ? filter_var( wp_unslash( $_GET['validate_jetpack_protect_recovery'] ) ) : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nothing on the site is changed in response to this request.
				'user_id'                           => isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nothing on the site is changed in response to this request.
				'action'                            => 'lostpassword',
			);
			if ( ! empty( $redirect ) ) {
				$args['redirect_to'] = $redirect;
			}
			$url = add_query_arg( $args, $url );
		}

		return $url;
	}

	/**
	 * Add arguments to login post url.
	 *
	 * @param string $url - the URL.
	 * @param string $path - the path.
	 * @param string $scheme -the scheme(?).
	 */
	public function add_args_to_login_post_url( $url, $path, $scheme ) {
		if ( $this->valid_blocked_user_id && ( 'login_post' === $scheme || 'login' === $scheme ) ) {
			$url = add_query_arg(
				array(
					'validate_jetpack_protect_recovery' => isset( $_GET['validate_jetpack_protect_recovery'] ) ? filter_var( wp_unslash( $_GET['validate_jetpack_protect_recovery'] ) ) : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nothing on the site is changed in response to this request.
					'user_id'                           => isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nothing on the site is changed in response to this request.
				),
				$url
			);

		}

		return $url;
	}

	/**
	 * Add arguments to login post url.
	 *
	 * @param string $url - the URL.
	 * @param string $redirect - where we want to redirect to.
	 * @param string $force_reauth -if we're forcing reauthorization.
	 */
	public function add_args_to_login_url( $url, $redirect, $force_reauth ) {
		if ( $this->valid_blocked_user_id ) {
			$args = array(
				'validate_jetpack_protect_recovery' => isset( $_GET['validate_jetpack_protect_recovery'] ) ? filter_var( wp_unslash( $_GET['validate_jetpack_protect_recovery'] ) ) : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nothing on the site is changed in response to this request.
				'user_id'                           => isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nothing on the site is changed in response to this request.
			);

			if ( ! empty( $redirect ) ) {
				$args['redirect_to'] = $redirect;
			}

			if ( ! empty( $force_reauth ) ) {
				$args['reauth'] = '1';
			}
			$url = add_query_arg( $args, $url );
		}

		return $url;
	}

	/**
	 * Check if user is blocked.
	 *
	 * @param string $user - the user.
	 */
	public function check_valid_blocked_user( $user ) {
		if ( $this->valid_blocked_user_id && $this->valid_blocked_user_id != $user->ID ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseNotEqual
			return new WP_Error( 'invalid_recovery_token', __( 'The recovery token is not valid for this user.', 'jetpack-waf' ) );
		}

		return $user;
	}

	/**
	 * Check if user is valid.
	 */
	public function is_blocked_user_valid() {
		if ( ! $this->can_send_recovery_emails ) {
			return false;
		}

		if ( $this->valid_blocked_user_id ) {
			return true;
		}

		if ( ! isset( $_GET['validate_jetpack_protect_recovery'], $_GET['user_id'] ) ) { // phpcs:ignore: WordPress.Security.NonceVerification.Recommended -- no changes made if this isn't set.
			return false;
		}

		if ( ! $this->is_valid_protect_recovery_key( filter_var( wp_unslash( $_GET['validate_jetpack_protect_recovery'] ) ), (int) $_GET['user_id'] ) ) { // phpcs:ignore: WordPress.Security.NonceVerification.Recommended -- no changes made if this isn't set.
			return false;
		}

		$this->valid_blocked_user_id = (int) $_GET['user_id']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nothing on the site is changed in response to this request.

		return true;
	}

	/**
	 * Checks if recovery key is valid.
	 *
	 * @param string $key - they recovery key.
	 * @param string $user_id - the User ID.
	 */
	public function is_valid_protect_recovery_key( $key, $user_id ) {

		$path     = sprintf( '/sites/%d/protect/recovery/confirm', Jetpack_Options::get_option( 'id' ) );
		$response = Client::wpcom_json_api_request_as_blog(
			$path,
			'1.1',
			array(
				'method' => 'post',
			),
			array(
				'token'   => $key,
				'user_id' => $user_id,
				'ip'      => $this->ip_address,
			)
		);

		$result = json_decode( wp_remote_retrieve_body( $response ) );

		if ( is_wp_error( $result ) || empty( $result ) || isset( $result->error ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Check if we should render the recovery form.
	 */
	public function render_and_die() {
		if ( ! $this->can_send_recovery_emails ) {
			$this->render_blocked_login_message();

			return;
		}

		if ( isset( $_GET['validate_jetpack_protect_recovery'] ) && ! empty( $_GET['user_id'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes, just throws invalid token error.
			$error = new WP_Error( 'invalid_token', __( "Oops, we couldn't validate the recovery token.", 'jetpack-waf' ) );
			$this->protect_die( $error );

			return;
		}

		if (
			isset( $_GET['jetpack-protect-recovery'] ) &&
			isset( $_POST['_wpnonce'] ) &&
			wp_verify_nonce( $_POST['_wpnonce'], 'bypass-protect' ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- WP Core doesn't unstrip or sanitize nonces either.
		) {
			$this->process_recovery_email();

			return;
		}

		if ( isset( $_GET['loggedout'] ) && 'true' === $_GET['loggedout'] ) {
			$this->protect_die( __( 'You successfully logged out.', 'jetpack-waf' ) );
		}

		$this->render_recovery_form();
	}

	/**
	 * Render the blocked login message.
	 */
	public function render_blocked_login_message() {
		$this->protect_die( $this->get_html_blocked_login_message() );
	}

	/**
	 * Process sending a recovery email.
	 */
	public function process_recovery_email() {
		$sent               = $this->send_recovery_email();
		$show_recovery_form = true;
		if ( is_wp_error( $sent ) ) {
			if ( 'email_already_sent' === $sent->get_error_code() ) {
				$show_recovery_form = false;
			}
			$this->protect_die( $sent, null, true, $show_recovery_form );
		} else {
			$this->render_recovery_success();
		}
	}

	/**
	 * Send the recovery form.
	 */
	public function send_recovery_email() {
		$email = isset( $_POST['email'] ) ? wp_unslash( $_POST['email'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only triggered after bypass-protect nonce check is done, and sanitization is checked on the next line.
		if ( sanitize_email( $email ) !== $email || ! is_email( $email ) ) {
			return new WP_Error( 'invalid_email', __( "Oops, looks like that's not the right email address. Please try again!", 'jetpack-waf' ) );
		}
		$user = get_user_by( 'email', trim( $email ) );

		if ( ! $user ) {
			return new WP_Error( 'invalid_user', __( "Oops, we couldn't find a user with that email. Please try again!", 'jetpack-waf' ) );
		}
		$this->email_address = $email;
		$path                = sprintf( '/sites/%d/protect/recovery/request', Jetpack_Options::get_option( 'id' ) );

		$response = Client::wpcom_json_api_request_as_blog(
			$path,
			'1.1',
			array(
				'method' => 'post',
			),
			array(
				'user_id' => $user->ID,
				'ip'      => $this->ip_address,
			)
		);

		$code   = wp_remote_retrieve_response_code( $response );
		$result = json_decode( wp_remote_retrieve_body( $response ) );

		if ( self::HTTP_STATUS_CODE_TOO_MANY_REQUESTS === $code ) {
			// translators: email address the recovery instructions were sent to.
			return new WP_Error( 'email_already_sent', sprintf( __( 'Recovery instructions were sent to %s. Check your inbox!', 'jetpack-waf' ), $this->email_address ) );
		} elseif ( is_wp_error( $result ) || empty( $result ) || isset( $result->error ) ) {
			return new WP_Error( 'email_send_error', __( 'Oops, we were unable to send a recovery email. Try again.', 'jetpack-waf' ) );
		}

		return true;
	}

	/**
	 * Prevent login by locking the login page.
	 *
	 * @param string $content - the content of the page.
	 * @param string $title - the page title.
	 * @param string $back_link - the back link.
	 * @param string $recovery_form - the recovery form.
	 */
	public function protect_die( $content, $title = null, $back_link = false, $recovery_form = false ) {
		if ( empty( $title ) ) {
			$title = __( 'Jetpack has locked your site\'s login page.', 'jetpack-waf' );
		}
		if ( is_wp_error( $content ) ) {
			$svg     = '<svg class="gridicon gridicons-notice" height="24" width="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g><path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm1 15h-2v-2h2v2zm0-4h-2l-.5-6h3l-.5 6z"/></g></svg>';
			$content = '<span class="error"> ' . $svg . $content->get_error_message() . '</span>';
		}
		$content = '<p>' . $content . '</p>';

		// If for some reason the login pop up box show up in the wp-admin.
		if ( isset( $_GET['interim-login'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no changes to the site itself, just rendering an error message.
			$content = '<style>html{ background-color: #fff; } #error-message { margin:0 auto; padding: 1em; box-shadow: none; } </style>' . $content;
		}
		$this->display_page( $title, $content, $back_link, $recovery_form );
	}

	/**
	 * Render the recovery form.
	 */
	public function render_recovery_form() {
		$content = $this->get_html_blocked_login_message();
		$this->protect_die( $content, null, null, true );
	}

	/**
	 * Render the recovery instructions.
	 */
	public function render_recovery_success() {
		// translators: the email address the recovery email was sent to.
		$this->protect_die( sprintf( __( 'Recovery instructions were sent to %s. Check your inbox!', 'jetpack-waf' ), $this->email_address ) );
	}

	/**
	 * Get the HTML for the blocked login message.
	 */
	public function get_html_blocked_login_message() {
		$icon = '<svg class="gridicon gridicons-spam" style="fill:#d94f4f" height="24" width="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g><path d="M17 2H7L2 7v10l5 5h10l5-5V7l-5-5zm-4 15h-2v-2h2v2zm0-4h-2l-.5-6h3l-.5 6z"/></g></svg>';
		$ip   = str_replace( 'http://', '', esc_url( 'http://' . $this->ip_address ) );
		return sprintf(
			// translators: the IP address that was flagged.
			__( '<p>Your IP address <code>%2$s</code> has been flagged for potential security violations. You can unlock your login by sending yourself a special link via email. <a href="%3$s">Learn More</a></p>', 'jetpack-waf' ), // phpcs:ignore WordPress.WP.I18n.NoHtmlWrappedStrings
			$icon,
			$ip,
			esc_url( self::get_help_url() )
		);
	}

	/**
	 * Get the HTML recovery form.
	 */
	public function get_html_recovery_form() {
		ob_start(); ?>
		<div>
			<form method="post" action="?jetpack-protect-recovery=true">
				<?php wp_nonce_field( 'bypass-protect' ); ?> 
				<p><label for="email"><?php esc_html_e( 'Your email', 'jetpack-waf' ); ?><br/></label>
					<input type="email" name="email" class="text-input"/>
					<input type="submit" class="button"
						value="<?php esc_attr_e( 'Send email', 'jetpack-waf' ); ?>"/>
				</p>
			</form>
		</div>

		<?php
		$contents = ob_get_contents();
		ob_end_clean();

		return $contents;
	}

	/**
	 * Display the page.
	 *
	 * @param string $title - the page title.
	 * @param string $message - the message we're sending.
	 * @param string $back_button - the back button.
	 * @param string $recovery_form - the recovery form.
	 */
	public function display_page( $title, $message, $back_button = false, $recovery_form = false ) {

		if ( ! headers_sent() ) {
			nocache_headers();
			header( 'Content-Type: text/html; charset=utf-8' );
		}

		$text_direction = 'ltr';
		if ( is_rtl() ) {
			$text_direction = 'rtl';
		}
		?>
		<!DOCTYPE html>
		<html xmlns="http://www.w3.org/1999/xhtml" 
		<?php
		if ( function_exists( 'language_attributes' ) && function_exists( 'is_rtl' ) ) {
			language_attributes();
		} else {
			echo "dir='$text_direction'"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		?>
		>
		<head>
			<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
			<meta name="viewport" content="width=device-width">
			<?php
			if ( get_option( 'blog_public' ) ) {
				echo "<meta name='robots' content='noindex,follow' />\n";
			} else {
				echo "<meta name='robots' content='noindex,nofollow' />\n";
			}
			?>
			<title><?php echo esc_html( $title ); ?></title>
			<style type="text/css">
				html {
					background: #f6f6f6;
				}

				body {
					color: #2e4453;
					font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
					margin: 2em auto;
					padding: 1em 2em;
					max-width: 460px;
					text-align: left;
				}
				body.is-rtl {
					text-align: right;
				}
				h1 {
					clear: both;
					color: #3d596d;
					font-size: 24px;
					margin:0 0 24px 0;
					padding: 0;
					font-weight: 400;
				}

				#error-message {
					box-sizing: border-box;
					background: white;
					box-shadow: 0 0 0 1px rgba(200, 215, 225, 0.5), 0 1px 2px #e9eff3;
					padding: 24px;
				}

				#error-message img {
					margin: 0 auto;
					display: block;
				}

				#error-page {
					margin-top: 50px;
				}

				#error-page p {
					font-size: 14px;
					line-height: 1.5;
					margin: 24px 0 0;
				}

				#error-page code {
					font-family: Consolas, Monaco, monospace;
				}

				ul li {
					margin-bottom: 10px;
					font-size: 14px;
				}

				a {
					color: #00aadc;
				}

				label {
					font-weight: bold;
					font-size:16px;
				}

				a:hover,
				a:active {
					color: #0085be;
				}

				a:focus {
					color: #124964;
					-webkit-box-shadow: 0 0 0 1px #4f94d4,
					0 0 2px 1px rgba(30, 140, 190, .8);
					box-shadow: 0 0 0 1px #4f94d4,
					0 0 2px 1px rgba(30, 140, 190, .8);
					outline: none;
				}

				.button {
					background: #00aadc;
					color: white;
					border-color: #008ab3;
					border-style: solid;
					border-width: 1px 1px 2px;
					cursor: pointer;
					display: inline-block;
					margin: 0;
					margin-right: 0px;
					outline: 0;
					overflow: hidden;
					font-weight: 500;
					text-overflow: ellipsis;
					text-decoration: none;
					vertical-align: top;
					box-sizing: border-box;
					font-size: 14px;
					line-height: 21px;
					border-radius: 4px;
					padding: 7px 14px 9px;
					-webkit-appearance: none;
					-moz-appearance: none;
					appearance: none;
					font-size: 14px;
					width: 100%;
				}

				.button:hover,
				.button:focus {
					border-color: #005082;
					outline: none;
				}

				.button:focus {
					border-color: #005082;
					-webkit-box-shadow: 0 0 3px rgba(0, 115, 170, .8);
					box-shadow: 0 0 3px rgba(0, 115, 170, .8);
					outline: none;
				}
				.button::-moz-focus-inner {
					border: 0;
				}

				.button:active {
					border-width: 2px 1px 1px;
				}
				.gridicon {
					fill: currentColor;
					vertical-align: middle;
				}
				#error-footer {
					padding: 16px;
				}
				#error-footer a {
					text-decoration: none;
					line-height:20px;
					font-size: 14px;
					color: #4f748e;
				}
				#error-footer a:hover {
					color: #2e4453;
				}
				#error-footer .gridicon{
					width: 16px;
				}
				#error-footer .gridicons-help {
					width: 24px;
					margin-right:8px;
				}

				.is-rtl #error-footer .gridicons-help {
					margin-left:8px;
				}

				.error {
					background: #d94f4f;
					color:#FFF;
					display: block;
					border-radius: 3px;
					line-height: 1.5;
					padding: 16px;
					padding-left: 42px;
				}
				.is-rtl .error {
					padding-right: 42px;
				}
				.error .gridicon {
					float: left;
					margin-left: -32px;
				}

				.is-rtl .error .gridicon {
					float: right;
					margin-right: -32px;
				}

				.text-input {
					margin: 0;
					padding: 7px 14px;
					width: 100%;
					color: #2e4453;
					font-size: 16px;
					line-height: 1.5;
					border: 1px solid #c8d7e1;
					background-color: white;
					transition: all .15s ease-in-out;
					box-sizing: border-box;
					margin: 8px 0 16px;
				}
				#image {
					display: block;
					width: 200px;
					margin: 0 auto;
				}
				<?php
				$rtl_class = '';
				if ( 'rtl' === $text_direction ) {
					$rtl_class = 'class="is-rtl"';
					echo 'body { font-family: Tahoma, Arial; }';
				}
				?>
			</style>
		</head>
		<body id="error-page" <?php echo $rtl_class; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>> 
			<h1 id="error-title"><?php echo esc_html( $title ); ?></h1>
			<div id="error-message">
				<svg id="image" xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" viewBox="0 0 250 134">
					<path fill="#E9EFF4" d="M205.2,129.8c3.7-0.7,7.4-0.9,11.1-1.1l5.5-0.1l5.5,0c3.7,0,7.4,0.1,11.1,0.2c3.7,0.1,7.4,0.3,11.1,0.8 c0.3,0,0.5,0.3,0.5,0.6c0,0.2-0.2,0.4-0.5,0.5c-3.7,0.5-7.4,0.6-11.1,0.8c-3.7,0.1-7.4,0.2-11.1,0.2l-5.5,0l-5.5-0.1 c-3.7-0.1-7.4-0.4-11.1-1.1c-0.1,0-0.2-0.2-0.2-0.3C205,129.9,205.1,129.8,205.2,129.8"/>
					<path fill="#E9EFF4" d="M0.2,130.9c3-0.7,5.9-0.9,8.9-1.1l4.4-0.1l4.4,0c3,0,5.9,0.1,8.9,0.2c3,0.1,5.9,0.3,8.9,0.8 c0.3,0,0.5,0.3,0.4,0.6c0,0.2-0.2,0.4-0.4,0.4c-3,0.5-5.9,0.6-8.9,0.8c-3,0.1-5.9,0.2-8.9,0.2l-4.4,0l-4.4-0.1 c-3-0.1-5.9-0.4-8.9-1.1c-0.1,0-0.2-0.2-0.2-0.3C0,131,0.1,130.9,0.2,130.9"/>
					<path fill="#C8D7E2" d="M101.6,130.1H70.1V52.5c0-8.5,6.9-15.3,15.3-15.3h16.1V130.1z"/>
					<path fill="#0DA9DD" d="M191.5,130.1h-73.8v-5.4c0-8.9,7.2-16.1,16.1-16.1h57.7V130.1z"/>
					<path fill="#C7E9F5" d="M55.2,25.6l-0.1,9.8L55,57l-0.1,21.6c0,0.2,0.2,0.4,0.4,0.4c0.2,0,0.4-0.2,0.4-0.4L56.6,57l0.8-21.6 c0.1-3.3,0.2-6.5,0.3-9.8H55.2z"/>
					<path fill="#C7E9F5" d="M203.1,25.6l0.1,18.1c0.2,28.8,0.4,57.6,1.2,86.3c0,0.4,0.4,0.8,0.8,0.8c0.4,0,0.8-0.3,0.8-0.8 c0.8-28.8,1-57.6,1.2-86.3l0.1-18.1H203.1z"/>
					<path fill="#7FD3F2" d="M55.3,25.6v-8.2v-6.8c0-5.9,4-10.7,9-10.7h134c5,0,9,4.8,9,10.7v14.9H55.3z"/>
					<path fill="#005083" d="M210.7,25.6c-13.3,1.1-26.7,1-40,1l-40,0.2l-40-0.2c-13.3-0.1-26.7,0-40-1V25c13.3-1.1,26.7-1,40-1l40-0.2 l40,0.2c13.3,0.1,26.7,0,40,1V25.6z"/>
					<polygon fill="#C7E9F5" points="168.7,95.6 117.7,95.6 117.7,44.6 	"/>
					<path fill="#C8D7E2" d="M191.5,56.5c0,11-8.9,19.9-19.9,19.9c-11,0-19.9-8.9-19.9-19.9c0-11,8.9-19.9,19.9-19.9 C182.6,36.6,191.5,45.5,191.5,56.5"/>
					<path fill="#FFFFFF" d="M213.2,95.5c-3.3-5.1-3.2-16.7-3.2-28.4h-32.3c0,0-5.2,25.5,4.6,33c7.5-0.1,29.9-0.6,29.9-0.6"/>
					<path fill="#C8D7E2" d="M213.5,95.3l-0.1-0.1l-0.3-0.5c-0.2-0.4-0.3-0.7-0.5-1.1c-0.3-0.8-0.5-1.6-0.7-2.4c-0.1-0.5-0.2-1.1-0.3-1.6 c-0.4,0-0.8,0-1.2,0c0.5,2.1,1.1,4.3,2.4,6.1l0.2,0.2c0.2,0,0.4-0.1,0.5-0.3C213.6,95.5,213.6,95.4,213.5,95.3L213.5,95.3z"/>
					<path fill="#C8D7E2" d="M212.5,98.6c-0.1,0-0.2,0-0.3,0l-0.1,0H212l-0.3,0l-0.6,0l-1.3,0l-2.5,0l-5,0l-19.5,0.2 c-1.9-1.7-3.1-4.1-3.8-6.5c-0.8-2.6-1.1-5.4-1.2-8.2c-0.2-5.2,0.3-10.4,1.1-15.6l5.7-0.1c0-0.9,0-1.8,0-2.6l-4.4,0l-2.5,0 c-0.4,0-0.8,0.2-1,0.5c-0.1,0.2-0.2,0.3-0.3,0.5l-0.1,0.3l-0.2,1.2c-0.3,1.7-0.5,3.3-0.7,5c-0.3,3.3-0.5,6.7-0.4,10.1 c0.1,3.4,0.5,6.7,1.5,10c0.5,1.6,1.2,3.2,2.2,4.7c0.5,0.7,1,1.4,1.7,2c0.3,0.3,0.6,0.6,1,0.9l0.1,0.1c0.1,0,0.2,0.1,0.3,0.2 c0.2,0.1,0.5,0.1,0.6,0.1l0.6,0l20-0.6l5-0.2l2.5-0.1l1.2,0l0.3,0l0.2,0c0,0,0.3,0,0.4-0.1c0.3-0.2,0.5-0.5,0.5-0.9 C213.1,99.1,212.9,98.7,212.5,98.6z"/>
					<path fill="#FFFFFF" d="M223.1,84.8c-3.3-5.1-4.8-16.7-4.8-28.4h-32.3c0,0-3.5,25.5,6.3,33c7.5-0.1,29.9-0.6,29.9-0.6"/>
					<path fill="#C8D7E2" d="M222.9,84.9c-1.3-2.1-2.2-4.4-2.8-6.7c-0.6-2.4-1.1-4.8-1.5-7.2c-0.7-4.8-1-9.1-1-13.9l0,0l-31,0.1l0,0 c-0.4,2.8-0.5,5.1-0.5,7.9c-0.1,2.9,0,5.7,0.3,8.6c0.3,2.8,0.8,5.7,1.7,8.3c0.9,2.6,2.3,5.2,4.5,6.9l-0.4-0.1l14.9-0.2 c5-0.1,10-0.1,14.9-0.1c0.1,0,0.3,0.1,0.3,0.3c0,0.1-0.1,0.3-0.2,0.3c-5,0.2-10,0.4-14.9,0.5l-14.9,0.4c-0.1,0-0.3,0-0.4-0.1l0,0 c-2.5-1.9-3.9-4.7-5-7.4c-1-2.8-1.5-5.7-1.9-8.6c-0.3-2.9-0.4-5.8-0.4-8.8c0.1-2.9,0.2-5.8,0.6-8.8c0-0.4,0.4-0.6,0.7-0.6h0 l32.3,0.1h0c0.3,0,0.6,0.3,0.6,0.6v0c0,4.8,0.2,9.6,0.7,14.4c0.3,2.4,0.6,4.8,1.2,7.1c0.5,2.3,1.2,4.7,2.4,6.8c0,0.1,0,0.1,0,0.2 C223.1,85,223,85,222.9,84.9"/>
					<path fill="#C8D7E2" d="M192.1,67.1c1.6-0.9,3.4-1.2,5.1-1.3c1.7-0.2,3.5-0.2,5.2-0.2c3.5,0.1,6.9,0.2,10.3,1c0.1,0,0.2,0.2,0.2,0.3 c0,0.1-0.1,0.2-0.2,0.2c-3.4,0.2-6.9,0-10.3,0c-1.7,0-3.4,0-5.1,0c-1.7,0-3.4,0.1-5.1,0.3l0,0c-0.1,0-0.1,0-0.1-0.1 C192,67.2,192.1,67.1,192.1,67.1"/>
					<path fill="#C8D7E2" d="M194.1,74c1.4,0,2.7,0,4.1,0c1.4,0,2.7,0,4.1,0c2.7,0,5.4-0.1,8.2-0.2c0.1,0,0.3,0.1,0.3,0.3 c0,0.1-0.1,0.2-0.2,0.3c-1.3,0.5-2.7,0.7-4.1,0.9c-1.4,0.2-2.8,0.2-4.2,0.3c-1.4,0-2.8,0-4.2-0.2c-1.4-0.2-2.8-0.4-4.1-1.1 c-0.1,0-0.1-0.1,0-0.2C193.9,74.1,194,74,194.1,74L194.1,74z"/>
					<path fill="#86A6BD" d="M40.2,88.6c-0.5,0-0.8-0.4-0.9-0.9l-0.1-8.2c0-0.7,0-1.4,0-2.1c0.1-0.7,0.2-1.5,0.4-2.2c0.4-1.4,1-2.8,1.9-4 c1.7-2.5,4.3-4.3,7.1-5.1c0.7-0.2,1.5-0.3,2.2-0.5c0.7-0.1,1.5-0.1,2.2-0.1c1.3,0,2.9,0,4.4,0.4c2.9,0.7,5.6,2.5,7.4,4.9 c0.9,1.2,1.6,2.6,2.1,4c0.5,1.4,0.6,3,0.6,4.4l0,16.4c0,0.7-0.6,1.3-1.3,1.3l-6.7,0c-0.7,0-1.3-0.6-1.3-1.3v0l0-10.8l0-5.4 c0-1.4-0.7-2.8-1.8-3.5c-0.6-0.4-1.3-0.6-2-0.7c-0.7,0-1.9,0-2.5,0c-1.4,0.1-2.7,1-3.3,2.3c-0.3,0.7-0.4,1.3-0.4,2.1l0,2.7 l-0.1,5.4l0,0c0,0.5-0.4,0.9-1,0.9"/>
					<path fill="#FFFFFF" d="M41.1,86.9l0.1-7.3c-0.1-2.6,0.7-5,2.1-7.1c1.4-2,3.6-3.5,5.9-4.1c0.6-0.2,1.2-0.3,1.8-0.3 c0.6,0,1.2-0.1,1.9,0c1.4,0,2.5,0,3.7,0.4c2.4,0.6,4.5,2,5.9,4c0.7,1,1.3,2.1,1.6,3.2c0.4,1.2,0.5,2.3,0.5,3.7l0,15.1l0,0l-4.2,0 l0-9.5l0-5.4c0-2.2-1.2-4.4-3-5.5c-0.9-0.6-2-0.9-3.1-1c-1.1,0-1.7,0-2.9,0c-2.2,0.2-4.2,1.7-5.1,3.6c-0.5,0.9-0.7,2.1-0.6,3.1 l0,2.7l0.1,4.4l0,0L41.1,86.9L41.1,86.9"/>
					<path fill="#86A6BD" d="M36.3,133c-1.9,0-3.8-1.1-4.8-2.8c-0.5-0.8-0.7-1.8-0.7-2.8l0-2.4l0-9.6l-0.1-9.6l0-4.8c0-0.7,0-1.8,0.3-2.8 c0.3-1,0.9-1.8,1.7-2.5c0.8-0.6,1.7-1.1,2.7-1.3c1.1-0.2,1.8-0.1,2.6-0.1l4.8,0l9.6-0.1l19.2,0c2.1,0,4.1,1.2,5.1,3 c0.5,0.9,0.8,2,0.8,3l0,2.4l0,9.6l-0.1,9.6l0,4.8c0,0.7,0,1.8-0.4,2.8c-0.3,0.9-1,1.8-1.7,2.4c-0.8,0.6-1.7,1.1-2.7,1.2 c-1.1,0.1-1.8,0-2.6,0.1l-4.8,0l-9.6-0.1L36.3,133z"/>
					<path fill="#FFFFFF" d="M74.8,112.3l-0.1-9.6l0-2.4c0-0.6-0.1-1.1-0.4-1.6c-0.6-1-1.7-1.6-2.8-1.6l-19.2,0L42.7,97l-4.8,0 c-0.8,0-1.7,0-2.2,0c-0.6,0.1-1.1,0.3-1.6,0.7c-0.5,0.4-0.8,0.9-1,1.4c-0.2,0.6-0.2,1.1-0.2,2l0,4.8l-0.1,9.6l0,9.6l0,2.4 c0,0.6,0.2,1.3,0.5,1.8c0.6,1.1,1.9,1.8,3.1,1.8l19.2-0.1l9.6-0.1l4.8,0c0.8,0,1.7,0,2.2-0.1c0.6-0.1,1.2-0.4,1.6-0.8 c0.5-0.4,0.8-0.9,1-1.5c0.2-0.6,0.2-1.1,0.2-2l0-4.8L74.8,112.3z"/>
					<path fill="#86A6BD" d="M48.1,121.4l2.9-6.2c0.3-0.6,0.2-1.3-0.3-1.8c-1-1-1.5-2.5-1.2-4c0.3-1.7,1.7-3.1,3.4-3.4 c2.9-0.6,5.4,1.6,5.4,4.4c0,1.2-0.5,2.3-1.3,3.1c-0.5,0.5-0.6,1.2-0.3,1.8l2.9,6.2c0.1,0.2-0.1,0.5-0.3,0.5H48.4 C48.1,121.9,48,121.6,48.1,121.4"/>
				</svg>

				<?php echo $message; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- message includes HTML that's marked up ourselves. ?>
				<?php
				if ( $recovery_form ) {
					echo $this->get_html_recovery_form(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- content is escaped in the function.
				}
				?>
			</div>
			<div id="error-footer">
			<?php
			if ( $back_button && ! $recovery_form ) {
				if ( 'rtl' === $text_direction ) {
					$back_button_icon = '<svg class="gridicon gridicons-arrow-right" height="24" width="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g><path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8-8-8z"/></g></svg>';
				} else {
					$back_button_icon = '<svg class="gridicon gridicons-arrow-left" height="24" width="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/></g></svg>';
				}
				?>
				<a href='javascript:history.back()'
				<?php
				printf(
					/* translators: %s is HTML markup, for a back icon. */
					__( '%s Back', 'jetpack-waf' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					$back_button_icon // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				);
				?>
				</a>
				<?php
			} else {
				$help_icon = '<svg class="gridicon gridicons-help" height="24" width="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g><path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm1 16h-2v-2h2v2zm0-4.14V15h-2v-2c0-.552.448-1 1-1 1.103 0 2-.897 2-2s-.897-2-2-2-2 .897-2 2H8c0-2.21 1.79-4 4-4s4 1.79 4 4c0 1.862-1.278 3.413-3 3.86z"/></g></svg>';
				?>
					<a href="<?php echo esc_url( self::get_help_url() ); ?>" rel="noopener noreferrer" target="_blank">
						<?php
						printf(
							/* translators: %s is HTML markup, for a help icon. */
							__( '%s Get help unlocking your site', 'jetpack-waf' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							$help_icon // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						);
						?>
					</a>
			<?php } ?>
			</div>
		</body>
		</html>
		<?php
		die();
	}
}
