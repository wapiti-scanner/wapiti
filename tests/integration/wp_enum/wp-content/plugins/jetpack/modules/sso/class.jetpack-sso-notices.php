<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * A collection of helper functions used in the SSO module.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Redirect;

if ( ! class_exists( 'Jetpack_SSO_Notices' ) ) :

	/**
	 * A collection of helper functions used in the SSO module.
	 *
	 * @since 4.4.0
	 */
	class Jetpack_SSO_Notices {
		/**
		 * Error message displayed on the login form when two step is required and
		 * the user's account on WordPress.com does not have two step enabled.
		 *
		 * @since 2.7
		 * @param string $message Error message.
		 * @return string
		 **/
		public static function error_msg_enable_two_step( $message ) {
			$error = sprintf(
				wp_kses(
				/* translators: URL to settings page */
					__(
						'Two-Step Authentication is required to access this site. Please visit your <a href="%1$s" rel="noopener noreferrer" target="_blank">Security Settings</a> to configure <a href="%2$s" rel="noopener noreferrer" target="_blank">Two-step Authentication</a> for your account.',
						'jetpack'
					),
					array( 'a' => array( 'href' => array() ) )
				),
				Redirect::get_url( 'calypso-me-security-two-step' ),
				Redirect::get_url( 'wpcom-support-security-two-step-authentication' )
			);

			$message .= sprintf( '<p class="message" id="login_error">%s</p>', $error );

			return $message;
		}

		/**
		 * Error message displayed when the user tries to SSO, but match by email
		 * is off and they already have an account with their email address on
		 * this site.
		 *
		 * @param string $message Error message.
		 * @return string
		 */
		public static function error_msg_email_already_exists( $message ) {
			$error = sprintf(
				wp_kses(
				/* translators: login URL */
					__(
						'You already have an account on this site. Please <a href="%1$s">sign in</a> with your username and password and then connect to WordPress.com.',
						'jetpack'
					),
					array( 'a' => array( 'href' => array() ) )
				),
				esc_url_raw( add_query_arg( 'jetpack-sso-show-default-form', '1', wp_login_url() ) )
			);

			$message .= sprintf( '<p class="message" id="login_error">%s</p>', $error );

			return $message;
		}

		/**
		 * Error message that is displayed when the current site is in an identity crisis and SSO can not be used.
		 *
		 * @since 4.3.2
		 *
		 * @param string $message Error Message.
		 *
		 * @return string
		 */
		public static function error_msg_identity_crisis( $message ) {
			$error    = esc_html__( 'Logging in with WordPress.com is not currently available because this site is experiencing connection problems.', 'jetpack' );
			$message .= sprintf( '<p class="message" id="login_error">%s</p>', $error );
			return $message;
		}

		/**
		 * Error message that is displayed when we are not able to verify the SSO nonce due to an XML error or
		 * failed validation. In either case, we prompt the user to try again or log in with username and password.
		 *
		 * @since 4.3.2
		 *
		 * @param string $message Error message.
		 *
		 * @return string
		 */
		public static function error_invalid_response_data( $message ) {
			$error    = esc_html__(
				'There was an error logging you in via WordPress.com, please try again or try logging in with your username and password.',
				'jetpack'
			);
			$message .= sprintf( '<p class="message" id="login_error">%s</p>', $error );
			return $message;
		}

		/**
		 * Error message that is displayed when we were not able to automatically create an account for a user
		 * after a user has logged in via SSO. By default, this message is triggered after trying to create an account 5 times.
		 *
		 * @since 4.3.2
		 *
		 * @param string $message Error message.
		 *
		 * @return string
		 */
		public static function error_unable_to_create_user( $message ) {
			$error    = esc_html__(
				'There was an error creating a user for you. Please contact the administrator of your site.',
				'jetpack'
			);
			$message .= sprintf( '<p class="message" id="login_error">%s</p>', $error );
			return $message;
		}

		/**
		 * When the default login form is hidden, this method is called on the 'authenticate' filter with a priority of 30.
		 * This method disables the ability to submit the default login form.
		 *
		 * @param WP_User|WP_Error $user Either the user attempting to login or an existing authentication failure.
		 *
		 * @return WP_Error
		 */
		public static function disable_default_login_form( $user ) {
			if ( is_wp_error( $user ) ) {
				return $user;
			}

			/**
			 * Since we're returning an error that will be shown as a red notice, let's remove the
			 * informational "blue" notice.
			 */
			remove_filter( 'login_message', array( 'Jetpack_SSO_Notices', 'msg_login_by_jetpack' ) );
			return new WP_Error( 'jetpack_sso_required', self::get_sso_required_message() );
		}

		/**
		 * Message displayed when the site admin has disabled the default WordPress
		 * login form in Settings > General > Secure Sign On
		 *
		 * @since 2.7
		 * @param string $message Error message.
		 *
		 * @return string
		 **/
		public static function msg_login_by_jetpack( $message ) {
			$message .= sprintf( '<p class="message">%s</p>', self::get_sso_required_message() );
			return $message;
		}

		/**
		 * Get the message for SSO required.
		 *
		 * @return string
		 */
		public static function get_sso_required_message() {
			$msg = esc_html__(
				'A WordPress.com account is required to access this site. Click the button below to sign in or create a free WordPress.com account.',
				'jetpack'
			);

			/**
			 * Filter the message displayed when the default WordPress login form is disabled.
			 *
			 * @module sso
			 *
			 * @since 2.8.0
			 *
			 * @param string $msg Disclaimer when default WordPress login form is disabled.
			 */
			return apply_filters( 'jetpack_sso_disclaimer_message', $msg );
		}

		/**
		 * Message displayed when the user can not be found after approving the SSO process on WordPress.com
		 *
		 * @param string $message Error message.
		 *
		 * @return string
		 */
		public static function cant_find_user( $message ) {
			$error = __(
				"We couldn't find your account. If you already have an account, make sure you have connected to WordPress.com.",
				'jetpack'
			);

			/**
			 * Filters the "couldn't find your account" notice after an attempted SSO.
			 *
			 * @module sso
			 *
			 * @since 10.5.0
			 *
			 * @param string $error Error text.
			 */
			$error = apply_filters( 'jetpack_sso_unknown_user_notice', $error );

			$message .= sprintf( '<p class="message" id="login_error">%s</p>', esc_html( $error ) );

			return $message;
		}

		/**
		 * Error message that is displayed when the current site is in an identity crisis and SSO can not be used.
		 *
		 * @since 4.4.0
		 *
		 * @param string $message Error message.
		 *
		 * @return string
		 */
		public static function sso_not_allowed_in_staging( $message ) {
			$error = __(
				'Logging in with WordPress.com is disabled for sites that are in staging mode.',
				'jetpack'
			);

			/**
			 * Filters the disallowed notice for staging sites attempting SSO.
			 *
			 * @module sso
			 *
			 * @since 10.5.0
			 *
			 * @param string $error Error text.
			 */
			$error    = apply_filters( 'jetpack_sso_disallowed_staging_notice', $error );
			$message .= sprintf( '<p class="message">%s</p>', esc_html( $error ) );
			return $message;
		}
	}

endif;
