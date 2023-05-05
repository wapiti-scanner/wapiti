<?php
/**
 * Tracks class.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Plugin;

use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\IP\Utils as IP_Utils;
use Automattic\Jetpack\Tracking as Tracks;

/**
 * Tracks class.
 */
class Tracking {
	/**
	 * Tracking object.
	 *
	 * @var Tracks
	 *
	 * @access private
	 */
	private $tracking;
	/**
	 * Prevents the Tracking from being intialized more then once.
	 *
	 * @var bool
	 */
	private $initalized = false;

	/**
	 * Initialization function.
	 */
	public function init() {
		if ( $this->initalized ) {
			return;
		}
		$this->initalized = true;
		$this->tracking   = new Tracks( 'jetpack' );

		// For tracking stuff via js/ajax.
		add_action( 'admin_enqueue_scripts', array( $this->tracking, 'enqueue_tracks_scripts' ) );

		add_action( 'jetpack_activate_module', array( $this, 'jetpack_activate_module' ), 1, 1 );
		add_action( 'jetpack_deactivate_module', array( $this, 'jetpack_deactivate_module' ), 1, 1 );
		add_action( 'jetpack_user_authorized', array( $this, 'jetpack_user_authorized' ) );
		add_action( 'wp_login_failed', array( $this, 'wp_login_failed' ) );

		// Tracking XMLRPC server events.
		add_action( 'jetpack_xmlrpc_server_event', array( $this, 'jetpack_xmlrpc_server_event' ), 10, 4 );

		// Track that we've begun verifying the previously generated secret.
		add_action( 'jetpack_verify_secrets_begin', array( $this, 'jetpack_verify_secrets_begin' ), 10, 2 );
		add_action( 'jetpack_verify_secrets_success', array( $this, 'jetpack_verify_secrets_success' ), 10, 2 );
		add_action( 'jetpack_verify_secrets_fail', array( $this, 'jetpack_verify_secrets_fail' ), 10, 3 );

		add_action( 'jetpack_verify_api_authorization_request_error_double_encode', array( $this, 'jetpack_verify_api_authorization_request_error_double_encode' ) );
		add_action( 'jetpack_connection_register_fail', array( $this, 'jetpack_connection_register_fail' ), 10, 2 );
		add_action( 'jetpack_connection_register_success', array( $this, 'jetpack_connection_register_success' ) );
	}

	/**
	 * Track that a specific module has been activated.
	 *
	 * @access public
	 *
	 * @param string $module Module slug.
	 */
	public function jetpack_activate_module( $module ) {
		$this->tracking->record_user_event( 'module_activated', array( 'module' => $module ) );
	}

	/**
	 * Track that a specific module has been deactivated.
	 *
	 * @access public
	 *
	 * @param string $module Module slug.
	 */
	public function jetpack_deactivate_module( $module ) {
		$this->tracking->record_user_event( 'module_deactivated', array( 'module' => $module ) );
	}

	/**
	 * Track that the user has successfully received an auth token.
	 *
	 * @access public
	 */
	public function jetpack_user_authorized() {
		$user_id = get_current_user_id();
		$anon_id = get_user_meta( $user_id, 'jetpack_tracks_anon_id', true );

		if ( $anon_id ) {
			$this->tracking->record_user_event( '_aliasUser', array( 'anonId' => $anon_id ) );
			delete_user_meta( $user_id, 'jetpack_tracks_anon_id' );
			if ( ! headers_sent() ) {
				setcookie( 'tk_ai', 'expired', time() - 1000, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), false );  // phpcs:ignore Jetpack.Functions.SetCookie -- Want this accessible.
			}
		}

		$connection_manager = new Connection_Manager();
		$wpcom_user_data    = $connection_manager->get_connected_user_data( $user_id );
		if ( isset( $wpcom_user_data['ID'] ) ) {
			update_user_meta( $user_id, 'jetpack_tracks_wpcom_id', $wpcom_user_data['ID'] );
		}

		$this->tracking->record_user_event( 'wpa_user_linked', array() );
	}

	/**
	 * Track that we've begun verifying the secrets.
	 *
	 * @access public
	 *
	 * @param string   $action Type of secret (one of 'register', 'authorize', 'publicize').
	 * @param \WP_User $user The user object.
	 */
	public function jetpack_verify_secrets_begin( $action, $user ) {
		$this->tracking->record_user_event( "jpc_verify_{$action}_begin", array(), $user );
	}

	/**
	 * Track that we've succeeded in verifying the secrets.
	 *
	 * @access public
	 *
	 * @param string   $action Type of secret (one of 'register', 'authorize', 'publicize').
	 * @param \WP_User $user The user object.
	 */
	public function jetpack_verify_secrets_success( $action, $user ) {
		$this->tracking->record_user_event( "jpc_verify_{$action}_success", array(), $user );
	}

	/**
	 * Track that we've failed verifying the secrets.
	 *
	 * @access public
	 *
	 * @param string    $action Type of secret (one of 'register', 'authorize', 'publicize').
	 * @param \WP_User  $user The user object.
	 * @param \WP_Error $error Error object.
	 */
	public function jetpack_verify_secrets_fail( $action, $user, $error ) {
		$this->tracking->record_user_event(
			"jpc_verify_{$action}_fail",
			array(
				'error_code'    => $error->get_error_code(),
				'error_message' => $error->get_error_message(),
			),
			$user
		);
	}

	/**
	 * Track a failed login attempt.
	 *
	 * @access public
	 *
	 * @param string $login Username or email address.
	 */
	public function wp_login_failed( $login ) {
		$this->tracking->record_user_event(
			'failed_login',
			array(
				'origin_ip' => IP_Utils::get_ip(),
				'login'     => $login,
			)
		);
	}

	/**
	 * Track a connection failure at the registration step.
	 *
	 * @access public
	 *
	 * @param string|int $error      The error code.
	 * @param \WP_Error  $registered The error object.
	 */
	public function jetpack_connection_register_fail( $error, $registered ) {
		$this->tracking->record_user_event(
			'jpc_register_fail',
			array(
				'error_code'    => $error,
				'error_message' => $registered->get_error_message(),
			)
		);
	}

	/**
	 * Track that the registration step of the connection has been successful.
	 *
	 * @access public
	 *
	 * @param string $from The 'from' GET parameter.
	 */
	public function jetpack_connection_register_success( $from ) {
		$this->tracking->record_user_event(
			'jpc_register_success',
			array(
				'from' => $from,
			)
		);
	}

	/**
	 * Handles the jetpack_xmlrpc_server_event action that combines several types of events that
	 * happen during request serving.
	 *
	 * @param String                   $action the action name, i.e., 'remote_authorize'.
	 * @param String                   $stage  the execution stage, can be 'begin', 'success', 'error', etc.
	 * @param array|WP_Error|IXR_Error $parameters (optional) extra parameters to be passed to the tracked action.
	 * @param WP_User                  $user (optional) the acting user.
	 */
	public function jetpack_xmlrpc_server_event( $action, $stage, $parameters = array(), $user = null ) {

		if ( is_wp_error( $parameters ) ) {
			$parameters = array(
				'error_code'    => $parameters->get_error_code(),
				'error_message' => $parameters->get_error_message(),
			);
		} elseif ( is_a( $parameters, '\\IXR_Error' ) ) {
			$parameters = array(
				'error_code'    => $parameters->code,
				'error_message' => $parameters->message,
			);
		}

		$this->tracking->record_user_event( 'jpc_' . $action . '_' . $stage, $parameters, $user );
	}

	/**
	 * Track that the site is incorrectly double-encoding redirects from http to https.
	 *
	 * @access public
	 */
	public function jetpack_verify_api_authorization_request_error_double_encode() {
		$this->tracking->record_user_event( 'error_double_encode' );
	}
}
