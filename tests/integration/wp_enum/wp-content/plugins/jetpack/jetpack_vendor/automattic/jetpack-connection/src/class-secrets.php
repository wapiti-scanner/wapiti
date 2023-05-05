<?php
/**
 * The Jetpack Connection Secrets class file.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

use Jetpack_Options;
use WP_Error;

/**
 * The Jetpack Connection Secrets class that is used to manage secrets.
 */
class Secrets {

	const SECRETS_MISSING            = 'secrets_missing';
	const SECRETS_EXPIRED            = 'secrets_expired';
	const LEGACY_SECRETS_OPTION_NAME = 'jetpack_secrets';

	/**
	 * Deletes all connection secrets from the local Jetpack site.
	 */
	public function delete_all() {
		Jetpack_Options::delete_raw_option( 'jetpack_secrets' );
	}

	/**
	 * Runs the wp_generate_password function with the required parameters. This is the
	 * default implementation of the secret callable, can be overridden using the
	 * jetpack_connection_secret_generator filter.
	 *
	 * @return String $secret value.
	 */
	private function secret_callable_method() {
		$secret = wp_generate_password( 32, false );

		// Some sites may hook into the random_password filter and make the password shorter, let's make sure our secret has the required length.
		$attempts      = 1;
		$secret_length = strlen( $secret );
		while ( $secret_length < 32 && $attempts < 32 ) {
			++$attempts;
			$secret       .= wp_generate_password( 32, false );
			$secret_length = strlen( $secret );
		}
		return (string) substr( $secret, 0, 32 );
	}

	/**
	 * Generates two secret tokens and the end of life timestamp for them.
	 *
	 * @param String       $action       The action name.
	 * @param Integer|bool $user_id The user identifier. Defaults to `false`.
	 * @param Integer      $exp          Expiration time in seconds.
	 */
	public function generate( $action, $user_id = false, $exp = 600 ) {
		if ( false === $user_id ) {
			$user_id = get_current_user_id();
		}

		$callable = apply_filters( 'jetpack_connection_secret_generator', array( get_called_class(), 'secret_callable_method' ) );

		$secrets = Jetpack_Options::get_raw_option(
			self::LEGACY_SECRETS_OPTION_NAME,
			array()
		);

		$secret_name = 'jetpack_' . $action . '_' . $user_id;

		if (
			isset( $secrets[ $secret_name ] ) &&
			$secrets[ $secret_name ]['exp'] > time()
		) {
			return $secrets[ $secret_name ];
		}

		$secret_value = array(
			'secret_1' => call_user_func( $callable ),
			'secret_2' => call_user_func( $callable ),
			'exp'      => time() + $exp,
		);

		$secrets[ $secret_name ] = $secret_value;

		$res = Jetpack_Options::update_raw_option( self::LEGACY_SECRETS_OPTION_NAME, $secrets );
		return $res ? $secrets[ $secret_name ] : false;
	}

	/**
	 * Returns two secret tokens and the end of life timestamp for them.
	 *
	 * @param String  $action  The action name.
	 * @param Integer $user_id The user identifier.
	 * @return string|array an array of secrets or an error string.
	 */
	public function get( $action, $user_id ) {
		$secret_name = 'jetpack_' . $action . '_' . $user_id;
		$secrets     = Jetpack_Options::get_raw_option(
			self::LEGACY_SECRETS_OPTION_NAME,
			array()
		);

		if ( ! isset( $secrets[ $secret_name ] ) ) {
			return self::SECRETS_MISSING;
		}

		if ( $secrets[ $secret_name ]['exp'] < time() ) {
			$this->delete( $action, $user_id );
			return self::SECRETS_EXPIRED;
		}

		return $secrets[ $secret_name ];
	}

	/**
	 * Deletes secret tokens in case they, for example, have expired.
	 *
	 * @param String  $action  The action name.
	 * @param Integer $user_id The user identifier.
	 */
	public function delete( $action, $user_id ) {
		$secret_name = 'jetpack_' . $action . '_' . $user_id;
		$secrets     = Jetpack_Options::get_raw_option(
			self::LEGACY_SECRETS_OPTION_NAME,
			array()
		);
		if ( isset( $secrets[ $secret_name ] ) ) {
			unset( $secrets[ $secret_name ] );
			Jetpack_Options::update_raw_option( self::LEGACY_SECRETS_OPTION_NAME, $secrets );
		}
	}

	/**
	 * Verify a Previously Generated Secret.
	 *
	 * @param string $action   The type of secret to verify.
	 * @param string $secret_1 The secret string to compare to what is stored.
	 * @param int    $user_id  The user ID of the owner of the secret.
	 * @return WP_Error|string WP_Error on failure, secret_2 on success.
	 */
	public function verify( $action, $secret_1, $user_id ) {
		$allowed_actions = array( 'register', 'authorize', 'publicize' );
		if ( ! in_array( $action, $allowed_actions, true ) ) {
			return new WP_Error( 'unknown_verification_action', 'Unknown Verification Action', 400 );
		}

		$user = get_user_by( 'id', $user_id );

		/**
		 * We've begun verifying the previously generated secret.
		 *
		 * @since 1.7.0
		 * @since-jetpack 7.5.0
		 *
		 * @param string   $action The type of secret to verify.
		 * @param \WP_User $user The user object.
		 */
		do_action( 'jetpack_verify_secrets_begin', $action, $user );

		$return_error = function ( WP_Error $error ) use ( $action, $user ) {
			/**
			 * Verifying of the previously generated secret has failed.
			 *
			 * @since 1.7.0
			 * @since-jetpack 7.5.0
			 *
			 * @param string    $action  The type of secret to verify.
			 * @param \WP_User  $user The user object.
			 * @param WP_Error $error The error object.
			 */
			do_action( 'jetpack_verify_secrets_fail', $action, $user, $error );

			return $error;
		};

		$stored_secrets = $this->get( $action, $user_id );
		$this->delete( $action, $user_id );

		$error = null;
		if ( empty( $secret_1 ) ) {
			$error = $return_error(
				new WP_Error(
					'verify_secret_1_missing',
					/* translators: "%s" is the name of a paramter. It can be either "secret_1" or "state". */
					sprintf( __( 'The required "%s" parameter is missing.', 'jetpack-connection' ), 'secret_1' ),
					400
				)
			);
		} elseif ( ! is_string( $secret_1 ) ) {
			$error = $return_error(
				new WP_Error(
					'verify_secret_1_malformed',
					/* translators: "%s" is the name of a paramter. It can be either "secret_1" or "state". */
					sprintf( __( 'The required "%s" parameter is malformed.', 'jetpack-connection' ), 'secret_1' ),
					400
				)
			);
		} elseif ( empty( $user_id ) ) {
			// $user_id is passed around during registration as "state".
			$error = $return_error(
				new WP_Error(
					'state_missing',
					/* translators: "%s" is the name of a paramter. It can be either "secret_1" or "state". */
					sprintf( __( 'The required "%s" parameter is missing.', 'jetpack-connection' ), 'state' ),
					400
				)
			);
		} elseif ( ! ctype_digit( (string) $user_id ) ) {
			$error = $return_error(
				new WP_Error(
					'state_malformed',
					/* translators: "%s" is the name of a paramter. It can be either "secret_1" or "state". */
					sprintf( __( 'The required "%s" parameter is malformed.', 'jetpack-connection' ), 'state' ),
					400
				)
			);
		} elseif ( self::SECRETS_MISSING === $stored_secrets ) {
			$error = $return_error(
				new WP_Error(
					'verify_secrets_missing',
					__( 'Verification secrets not found', 'jetpack-connection' ),
					400
				)
			);
		} elseif ( self::SECRETS_EXPIRED === $stored_secrets ) {
			$error = $return_error(
				new WP_Error(
					'verify_secrets_expired',
					__( 'Verification took too long', 'jetpack-connection' ),
					400
				)
			);
		} elseif ( ! $stored_secrets ) {
			$error = $return_error(
				new WP_Error(
					'verify_secrets_empty',
					__( 'Verification secrets are empty', 'jetpack-connection' ),
					400
				)
			);
		} elseif ( is_wp_error( $stored_secrets ) ) {
			$stored_secrets->add_data( 400 );
			$error = $return_error( $stored_secrets );
		} elseif ( empty( $stored_secrets['secret_1'] ) || empty( $stored_secrets['secret_2'] ) || empty( $stored_secrets['exp'] ) ) {
			$error = $return_error(
				new WP_Error(
					'verify_secrets_incomplete',
					__( 'Verification secrets are incomplete', 'jetpack-connection' ),
					400
				)
			);
		} elseif ( ! hash_equals( $secret_1, $stored_secrets['secret_1'] ) ) {
			$error = $return_error(
				new WP_Error(
					'verify_secrets_mismatch',
					__( 'Secret mismatch', 'jetpack-connection' ),
					400
				)
			);
		}

		// Something went wrong during the checks, returning the error.
		if ( ! empty( $error ) ) {
			return $error;
		}

		/**
		 * We've succeeded at verifying the previously generated secret.
		 *
		 * @since 1.7.0
		 * @since-jetpack 7.5.0
		 *
		 * @param string   $action The type of secret to verify.
		 * @param \WP_User $user The user object.
		 */
		do_action( 'jetpack_verify_secrets_success', $action, $user );

		return $stored_secrets['secret_2'];
	}
}
