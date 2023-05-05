<?php
/**
 * The React initial state.
 *
 * @package automattic/jetpack-wordads
 */

namespace Automattic\Jetpack\WordAds;

use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Modules;
use Automattic\Jetpack\Status;
use Jetpack_Options;

/**
 * The React initial state.
 */
class Initial_State {
	/**
	 * Connection Manager
	 *
	 * @var Connection_Manager
	 */
	protected $connection_manager;

	/**
	 * Constructor
	 *
	 * @param Connection_Manager $connection_manager - Connection mananger instance.
	 */
	public function __construct( $connection_manager = null ) {
		$this->connection_manager = $connection_manager ? $connection_manager : new Connection_Manager( Package::SLUG );
	}

	/**
	 * Render JS for the initial state
	 *
	 * @return string - JS string.
	 */
	public function render() {
		return 'var WORDADS_DASHBOARD_INITIAL_STATE=JSON.parse(decodeURIComponent("' . rawurlencode( wp_json_encode( $this->get_initial_state() ) ) . '"));';
	}

	/**
	 * Get the initial state data.
	 *
	 * @return array
	 */
	public function get_initial_state() {
		return array(
			'siteData'        => array(
				'WP_API_root'       => esc_url_raw( rest_url() ),
				'WP_API_nonce'      => wp_create_nonce( 'wp_rest' ),
				'registrationNonce' => wp_create_nonce( 'jetpack-registration-nonce' ),
				'adminUrl'          => esc_url( admin_url() ),
				'blogId'            => Jetpack_Options::get_option( 'id', 0 ),
				// TODO: add WORDADS_PACKAGE_VERSION to a proper place after major PRs merged.
				'version'           => defined( 'WORDADS_PACKAGE_VERSION' ) ? WORDADS_PACKAGE_VERSION : 'dev',
				'calypsoSlug'       => ( new Status() )->get_site_suffix(),
			),
			'userData'        => array(
				'currentUser' => $this->current_user_data(),
			),
			'jetpackSettings' => array(
				'wordads' => ( new Modules() )->is_active( Package::SLUG ),
			),
			'features'        => array_map(
				'sanitize_text_field',
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				isset( $_GET['features'] ) ? explode( ',', wp_unslash( $_GET['features'] ) ) : array()
			),
		);
	}

	/**
	 * Gather data about the current user.
	 *
	 * @return array
	 */
	protected function current_user_data() {
		$current_user      = wp_get_current_user();
		$is_user_connected = $this->connection_manager->is_user_connected( $current_user->ID );
		$is_master_user    = $is_user_connected && (int) $current_user->ID && (int) Jetpack_Options::get_option( 'master_user' ) === (int) $current_user->ID;
		$dotcom_data       = $this->connection_manager->get_connected_user_data();

		$current_user_data = array(
			'isConnected' => $is_user_connected,
			'isMaster'    => $is_master_user,
			'username'    => $current_user->user_login,
			'id'          => $current_user->ID,
			'wpcomUser'   => $dotcom_data,
			'permissions' => array(
				'manage_options' => current_user_can( 'manage_options' ),
			),
		);

		return $current_user_data;
	}
}
