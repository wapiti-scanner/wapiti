<?php
/**
 * Connection Webhooks class.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

use Automattic\Jetpack\CookieState;
use Automattic\Jetpack\Roles;
use Automattic\Jetpack\Status\Host;
use Automattic\Jetpack\Tracking;
use Jetpack_Options;

/**
 * Connection Webhooks class.
 */
class Webhooks {

	/**
	 * The Connection Manager object.
	 *
	 * @var Manager
	 */
	private $connection;

	/**
	 * Webhooks constructor.
	 *
	 * @param Manager $connection The Connection Manager object.
	 */
	public function __construct( $connection ) {
		$this->connection = $connection;
	}

	/**
	 * Initialize the webhooks.
	 *
	 * @param Manager $connection The Connection Manager object.
	 */
	public static function init( $connection ) {
		$webhooks = new static( $connection );

		add_action( 'init', array( $webhooks, 'controller' ) );
		add_action( 'load-toplevel_page_jetpack', array( $webhooks, 'fallback_jetpack_controller' ) );
	}

	/**
	 * Jetpack plugin used to trigger this webhooks in Jetpack::admin_page_load()
	 *
	 * The Jetpack toplevel menu is still accessible for stand-alone plugins, and while there's no content for that page, there are still
	 * actions from Calypso and WPCOM that reach that route regardless of the site having the Jetpack plugin or not. That's why we are still handling it here.
	 */
	public function fallback_jetpack_controller() {
		$this->controller( true );
	}

	/**
	 * The "controller" decides which handler we need to run.
	 *
	 * @param bool $force Do not check if it's a webhook request and just run the controller.
	 */
	public function controller( $force = false ) {
		if ( ! $force ) {
			// The nonce is verified in specific handlers.
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( empty( $_GET['handler'] ) || 'jetpack-connection-webhooks' !== $_GET['handler'] ) {
				return;
			}
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['connect_url_redirect'] ) ) {
			$this->handle_connect_url_redirect();
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['action'] ) ) {
			return;
		}

		// The nonce is verified in specific handlers.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		switch ( $_GET['action'] ) {
			case 'authorize':
				$this->handle_authorize();
				$this->do_exit();
				break;
			case 'authorize_redirect':
				$this->handle_authorize_redirect();
				$this->do_exit();
				break;
			// Class Jetpack::admin_page_load() still handles other cases.
		}
	}

	/**
	 * Perform the authorization action.
	 */
	public function handle_authorize() {
		if ( $this->connection->is_connected() && $this->connection->is_user_connected() ) {
			$redirect_url = apply_filters( 'jetpack_client_authorize_already_authorized_url', admin_url() );
			wp_safe_redirect( $redirect_url );

			return;
		}
		do_action( 'jetpack_client_authorize_processing' );

		$data              = stripslashes_deep( $_GET );
		$data['auth_type'] = 'client';
		$roles             = new Roles();
		$role              = $roles->translate_current_user_to_role();
		$redirect          = isset( $data['redirect'] ) ? esc_url_raw( (string) $data['redirect'] ) : '';

		check_admin_referer( "jetpack-authorize_{$role}_{$redirect}" );

		$tracking = new Tracking();

		$result = $this->connection->authorize( $data );

		if ( is_wp_error( $result ) ) {
			do_action( 'jetpack_client_authorize_error', $result );

			$tracking->record_user_event(
				'jpc_client_authorize_fail',
				array(
					'error_code'    => $result->get_error_code(),
					'error_message' => $result->get_error_message(),
				)
			);
		} else {
			/**
			 * Fires after the Jetpack client is authorized to communicate with WordPress.com.
			 *
			 * @param int Jetpack Blog ID.
			 *
			 * @since 1.7.0
			 * @since-jetpack 4.2.0
			 */
			do_action( 'jetpack_client_authorized', Jetpack_Options::get_option( 'id' ) );

			$tracking->record_user_event( 'jpc_client_authorize_success' );
		}

		$fallback_redirect = apply_filters( 'jetpack_client_authorize_fallback_url', admin_url() );
		$redirect          = wp_validate_redirect( $redirect ) ? $redirect : $fallback_redirect;

		wp_safe_redirect( $redirect );
	}

	/**
	 * The authorhize_redirect webhook handler
	 */
	public function handle_authorize_redirect() {
		$authorize_redirect_handler = new Webhooks\Authorize_Redirect( $this->connection );
		$authorize_redirect_handler->handle();
	}

	/**
	 * The `exit` is wrapped into a method so we could mock it.
	 */
	protected function do_exit() {
		exit;
	}

	/**
	 * Handle the `connect_url_redirect` action,
	 * which is usually called to repeat an attempt for user to authorize the connection.
	 *
	 * @return void
	 */
	public function handle_connect_url_redirect() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes.
		$from = ! empty( $_GET['from'] ) ? sanitize_text_field( wp_unslash( $_GET['from'] ) ) : 'iframe';

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- no site changes, sanitization happens in get_authorization_url()
		$redirect = ! empty( $_GET['redirect_after_auth'] ) ? wp_unslash( $_GET['redirect_after_auth'] ) : false;

		add_filter( 'allowed_redirect_hosts', array( Host::class, 'allow_wpcom_environments' ) );

		if ( ! $this->connection->is_user_connected() ) {
			if ( ! $this->connection->is_connected() ) {
				$this->connection->register();
			}

			$connect_url = add_query_arg( 'from', $from, $this->connection->get_authorization_url( null, $redirect ) );

			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes.
			if ( isset( $_GET['notes_iframe'] ) ) {
				$connect_url .= '&notes_iframe';
			}
			wp_safe_redirect( $connect_url );
			$this->do_exit();
		} elseif ( ! isset( $_GET['calypso_env'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes.
			( new CookieState() )->state( 'message', 'already_authorized' );
			wp_safe_redirect( $redirect );
			$this->do_exit();
		} else {
			$connect_url = add_query_arg(
				array(
					'from'               => $from,
					'already_authorized' => true,
				),
				$this->connection->get_authorization_url()
			);
			wp_safe_redirect( $connect_url );
			$this->do_exit();
		}
	}
}
