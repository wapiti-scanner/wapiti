<?php
/**
 * The React initial state.
 *
 * @package automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search;

use Automattic\Jetpack\Connection\Manager as Connection_Manager;
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
	 * Search Module Control
	 *
	 * @var Module_Control
	 */
	protected $module_control;

	/**
	 * Constructor
	 *
	 * @param Connection_Manager $connection_manager - Connection mananger instance.
	 * @param Module_Control     $module_control - Module control instance.
	 */
	public function __construct( $connection_manager = null, $module_control = null ) {
		$this->connection_manager = $connection_manager ? $connection_manager : new Connection_Manager( Package::SLUG );
		$this->module_control     = $module_control ? $module_control : new Module_Control();
	}

	/**
	 * Render JS for the initial state
	 *
	 * @return string - JS string.
	 */
	public function render() {
		return 'var JETPACK_SEARCH_DASHBOARD_INITIAL_STATE=JSON.parse(decodeURIComponent("' . rawurlencode( wp_json_encode( $this->get_initial_state() ) ) . '"));';
	}

	/**
	 * Get the initial state data.
	 *
	 * @return array
	 */
	public function get_initial_state() {
		return array(
			'siteData'        => array(
				'WP_API_root'        => esc_url_raw( rest_url() ),
				'wpcomOriginApiUrl'  => $this->get_wp_api_root(),
				'WP_API_nonce'       => wp_create_nonce( 'wp_rest' ),
				'registrationNonce'  => wp_create_nonce( 'jetpack-registration-nonce' ),
				'purchaseToken'      => $this->get_purchase_token(),
				/**
				 * Whether promotions are visible or not.
				 *
				 * @param bool $are_promotions_active Status of promotions visibility. True by default.
				 */
				'showPromotions'     => apply_filters( 'jetpack_show_promotions', true ),
				'adminUrl'           => esc_url( admin_url() ),
				'blogId'             => Jetpack_Options::get_option( 'id', 0 ),
				'version'            => Package::VERSION,
				'calypsoSlug'        => ( new Status() )->get_site_suffix(),
				'title'              => get_bloginfo( 'name' ),
				'postTypes'          => $this->get_post_types_with_labels(),
				'isWpcom'            => Helper::is_wpcom(),
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				'isPlanJustUpgraded' => isset( $_GET['just_upgraded'] ) && wp_unslash( $_GET['just_upgraded'] ),
			),
			'userData'        => array(
				'currentUser' => $this->current_user_data(),
			),
			'jetpackSettings' => array(
				'search'                 => $this->module_control->is_active(),
				'instant_search_enabled' => $this->module_control->is_instant_search_enabled(),
			),
			'features'        => array_map(
				'sanitize_text_field',
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				isset( $_GET['features'] ) ? explode( ',', wp_unslash( $_GET['features'] ) ) : array()
			),
		);
	}

	/**
	 * Get API root.
	 *
	 * It return first party API root for WPCOM simple sites.
	 */
	protected function get_wp_api_root() {
		if ( ! Helper::is_wpcom() ) {
			return esc_url_raw( rest_url() );
		}
		// First party API prefix for WPCOM.
		return esc_url_raw( site_url( '/wp-json/wpcom-origin/' ) );
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

	/**
	 * Gets the post type labels for all of the site's post types (including custom post types)
	 *
	 * @return array
	 */
	protected function get_post_types_with_labels() {

		$args = array(
			'public' => true,
		);

		$post_types_with_labels = array();

		$post_types = get_post_types( $args, 'objects' );

		// We don't need all the additional post_type data, just the slug & label
		foreach ( $post_types as $post_type ) {
			$post_type_with_label = array(
				'slug'  => $post_type->name,
				'label' => $post_type->label,
			);

			$post_types_with_labels[ $post_type->name ] = $post_type_with_label;
		}
		return $post_types_with_labels;
	}

	/**
	 * Gets a purchase token that is used for Jetpack logged out visitor checkout.
	 * The purchase token should be appended to all CTA url's that lead to checkout.
	 *
	 * @return string|boolean
	 */
	protected function get_purchase_token() {
		if ( ! $this->current_user_can_purchase() ) {
			return false;
		}

		$purchase_token = Jetpack_Options::get_option( 'purchase_token', false );

		if ( $purchase_token ) {
			return $purchase_token;
		}
		// If the purchase token is not saved in the options table yet, then add it.
		Jetpack_Options::update_option( 'purchase_token', $this->generate_purchase_token(), true );
		return Jetpack_Options::get_option( 'purchase_token', false );
	}

	/**
	 * Generates a purchase token that is used for Jetpack logged out visitor checkout.
	 *
	 * @return string
	 */
	protected function generate_purchase_token() {
		return wp_generate_password( 12, false );
	}

	/**
	 * Determine if the current user is allowed to make Jetpack purchases without
	 * a WordPress.com account
	 *
	 * @return boolean True if the user can make purchases, false if not
	 */
	public function current_user_can_purchase() {
		// The site must be site-connected to Jetpack (no users connected).
		if ( ! $this->connection_manager->is_site_connection() ) {
			return false;
		}

		// Make sure only administrators can make purchases.
		if ( ! current_user_can( 'manage_options' ) ) {
			return false;
		}

		return true;
	}
}
