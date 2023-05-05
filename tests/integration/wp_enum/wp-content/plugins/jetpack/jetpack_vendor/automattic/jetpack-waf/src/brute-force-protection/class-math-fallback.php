<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

namespace Automattic\Jetpack\Waf\Brute_Force_Protection;

if ( ! class_exists( 'Brute_Force_Protection_Math_Authenticate' ) ) {

	/**
	 * The math captcha fallback if we can't talk to the Protect API
	 */
	class Brute_Force_Protection_Math_Authenticate {

		/**
		 * If the class is loaded.
		 *
		 * @var bool
		 */
		public static $loaded;

		/**
		 * Class constructor.
		 */
		public function __construct() {

			if ( self::$loaded ) {
				return;
			}

			self::$loaded = 1;

			add_action( 'login_form', array( $this, 'math_form' ) );

			if ( isset( $_POST['jetpack_protect_process_math_form'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- No changes made, just queues the math authenticator hook.
				add_action( 'init', array( $this, 'process_generate_math_page' ) );
			}
		}

		/**
		 * The timeout window.
		 */
		private static function time_window() {
			return ceil( time() / ( MINUTE_IN_SECONDS * 2 ) );
		}

		/**
		 * Verifies that a user answered the math problem correctly while logging in.
		 *
		 * @return bool Returns true if the math is correct
		 * @throws Error If insuffient $_POST variables are present.
		 * @throws Error Message if the math is wrong.
		 */
		public static function math_authenticate() {
			if ( isset( $_COOKIE['jpp_math_pass'] ) ) {
				$brute_force_protection = Brute_Force_Protection::instance();
				$transient              = $brute_force_protection->get_transient( 'jpp_math_pass_' . sanitize_key( $_COOKIE['jpp_math_pass'] ) );

				if ( ! $transient || $transient < 1 ) {
					self::generate_math_page();
				}
				return true;
			}

			$ans         = isset( $_POST['jetpack_protect_num'] ) ? (int) $_POST['jetpack_protect_num'] : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- answers are salted.
			$correct_ans = isset( $_POST['jetpack_protect_answer'] ) ? sanitize_key( $_POST['jetpack_protect_answer'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

			$time_window  = self::time_window();
			$salt         = get_site_option( 'jetpack_protect_key' ) . '|' . get_site_option( 'admin_email' ) . '|';
			$salted_ans_1 = hash_hmac( 'sha1', $ans, $salt . $time_window );
			$salted_ans_2 = hash_hmac( 'sha1', $ans, $salt . ( $time_window - 1 ) );

			if ( ! $correct_ans || ! $ans ) {
				self::generate_math_page();
			} elseif ( ! hash_equals( $salted_ans_1, $correct_ans ) && ! hash_equals( $salted_ans_2, $correct_ans ) ) {
				wp_die(
					wp_kses(
						__(
							'<strong>You failed to correctly answer the math problem.</strong> This is used to combat spam when Jetpack’s Brute Force Attack Protection API is unavailable. Please use your browser’s back button to return to the login form, press the "refresh" button to generate a new math problem, and try to log in again.',
							'jetpack-waf'
						),
						array( 'strong' => array() )
					),
					'',
					array( 'response' => 401 )
				);
			} else {
				return true;
			}
		}

		/**
		 * Creates an interim page to collect answers to a math captcha
		 *
		 * @param string $error - the error message.
		 */
		public static function generate_math_page( $error = false ) {
			ob_start();
			?>
			<h2><?php esc_html_e( 'Please solve this math problem to prove that you are not a bot. Once you solve it, you will need to log in again.', 'jetpack-waf' ); ?></h2>
			<?php if ( $error ) : ?>
				<h3><?php esc_html_e( 'Your answer was incorrect, please try again.', 'jetpack-waf' ); ?></h3>
			<?php endif ?>

			<form action="<?php echo esc_url( wp_login_url() ); ?>" method="post" accept-charset="utf-8">
				<?php self::math_form(); ?>
				<input type="hidden" name="jetpack_protect_process_math_form" value="1" id="jetpack_protect_process_math_form" />
				<p><input type="submit" value="<?php esc_attr_e( 'Continue &rarr;', 'jetpack-waf' ); ?>"></p>
			</form>
			<?php
			$mathpage = ob_get_contents();
			ob_end_clean();
			wp_die(
				$mathpage, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- content is escaped.
				'',
				array( 'response' => 401 )
			);
		}

		/**
		 * Generates the math page.
		 */
		public function process_generate_math_page() {
			$ans         = isset( $_POST['jetpack_protect_num'] ) ? (int) $_POST['jetpack_protect_num'] : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- answers are salted.
			$correct_ans = isset( $_POST['jetpack_protect_answer'] ) ? sanitize_key( $_POST['jetpack_protect_answer'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

			$time_window  = self::time_window();
			$salt         = get_site_option( 'jetpack_protect_key' ) . '|' . get_site_option( 'admin_email' ) . '|';
			$salted_ans_1 = hash_hmac( 'sha1', $ans, $salt . $time_window );
			$salted_ans_2 = hash_hmac( 'sha1', $ans, $salt . ( $time_window - 1 ) );

			if ( ! hash_equals( $salted_ans_1, $correct_ans ) && ! hash_equals( $salted_ans_2, $correct_ans ) ) {
				self::generate_math_page( true );
			} else {
				$temp_pass = substr( hash_hmac( 'sha1', wp_rand( 1, 100000000 ), get_site_option( 'jetpack_protect_key' ) ), 5, 25 );

				$brute_force_protection = Brute_Force_Protection::instance();
				$brute_force_protection->set_transient( 'jpp_math_pass_' . $temp_pass, 3, DAY_IN_SECONDS );
				setcookie( 'jpp_math_pass', $temp_pass, time() + DAY_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, false, true );
				remove_action( 'login_form', array( $this, 'math_form' ) );
				return true;
			}
		}

		/**
		 * Requires a user to solve a simple equation. Added to any WordPress login form.
		 *
		 * @return VOID outputs html
		 */
		public static function math_form() {
			// Check if jpp_math_pass cookie is set and it matches valid transient.
			if ( isset( $_COOKIE['jpp_math_pass'] ) ) {
				$brute_force_protection = Brute_Force_Protection::instance();
				$transient              = $brute_force_protection->get_transient( 'jpp_math_pass_' . sanitize_key( $_COOKIE['jpp_math_pass'] ) );

				if ( $transient && $transient > 0 ) {
					return '';
				}
			}

			$num1 = wp_rand( 0, 10 );
			$num2 = wp_rand( 1, 10 );
			$ans  = $num1 + $num2;

			$time_window = self::time_window();
			$salt        = get_site_option( 'jetpack_protect_key' ) . '|' . get_site_option( 'admin_email' ) . '|';
			$salted_ans  = hash_hmac( 'sha1', $ans, $salt . $time_window );
			?>
			<div style="margin: 5px 0 20px;">
				<p style="font-size: 14px;">
					<?php esc_html_e( 'Prove your humanity', 'jetpack-waf' ); ?>
				</p>
				<br/>
				<label for="jetpack_protect_answer" style="vertical-align:super;">
					<?php echo esc_html( "$num1 &nbsp; + &nbsp; $num2 &nbsp; = &nbsp;" ); ?>
				</label>
				<input type="number" id="jetpack_protect_answer" name="jetpack_protect_num" value="" size="2" style="width:50px;height:25px;vertical-align:middle;font-size:13px;" class="input" />
				<input type="hidden" name="jetpack_protect_answer" value="<?php echo esc_attr( $salted_ans ); ?>" />
			</div>
			<?php
		}

	}
}
