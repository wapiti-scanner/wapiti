<?php
/**
 * Scan product
 *
 * @package my-jetpack
 */

namespace Automattic\Jetpack\My_Jetpack\Products;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\My_Jetpack\Module_Product;
use Automattic\Jetpack\My_Jetpack\Wpcom_Products;
use Automattic\Jetpack\Redirect;
use Jetpack_Options;
use WP_Error;

/**
 * Class responsible for handling the Scan product
 */
class Scan extends Module_Product {

	/**
	 * The product slug
	 *
	 * @var string
	 */
	public static $slug = 'scan';

	/**
	 * The Jetpack module name
	 *
	 * @var string
	 */
	public static $module_name = 'scan';

	/**
	 * Get the internationalized product name
	 *
	 * @return string
	 */
	public static function get_name() {
		return __( 'Scan', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product title
	 *
	 * @return string
	 */
	public static function get_title() {
		return __( 'Jetpack Scan', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product description
	 *
	 * @return string
	 */
	public static function get_description() {
		return __( 'Stay one step ahead of threats', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product long description
	 *
	 * @return string
	 */
	public static function get_long_description() {
		return __( 'Automatic scanning and one-click fixes keep your site one step ahead of security threats and malware.', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized features list
	 *
	 * @return array Scan features list
	 */
	public static function get_features() {
		return array(
			_x( 'Automated daily scanning', 'Scan Product Feature', 'jetpack-my-jetpack' ),
			_x( 'One-click fixes for most issues', 'Scan Product Feature', 'jetpack-my-jetpack' ),
			_x( 'Instant email notifications', 'Scan Product Feature', 'jetpack-my-jetpack' ),
			_x( 'Access to latest Firewall rules', 'Scan Product Feature', 'jetpack-my-jetpack' ),
		);
	}

	/**
	 * Get the product princing details
	 *
	 * @return array Pricing details
	 */
	public static function get_pricing_for_ui() {
		return array_merge(
			array(
				'available'          => true,
				'wpcom_product_slug' => static::get_wpcom_product_slug(),
			),
			Wpcom_Products::get_product_pricing( static::get_wpcom_product_slug() )
		);
	}

	/**
	 * Get the WPCOM product slug used to make the purchase
	 *
	 * @return ?string
	 */
	public static function get_wpcom_product_slug() {
		return 'jetpack_scan';
	}

	/**
	 * Hits the wpcom api to check scan status.
	 *
	 * @todo Maybe add caching.
	 *
	 * @return Object|WP_Error
	 */
	private static function get_state_from_wpcom() {
		static $status = null;

		if ( $status !== null ) {
			return $status;
		}

		$site_id = Jetpack_Options::get_option( 'id' );

		$response = Client::wpcom_json_api_request_as_blog( sprintf( '/sites/%d/scan', $site_id ) . '?force=wpcom', '2', array( 'timeout' => 2 ), null, 'wpcom' );

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'scan_state_fetch_failed' );
		}

		$body   = wp_remote_retrieve_body( $response );
		$status = json_decode( $body );
		return $status;
	}

	/**
	 * Checks whether the current plan (or purchases) of the site already supports the product
	 *
	 * @return boolean
	 */
	public static function has_required_plan() {
		$scan_data = static::get_state_from_wpcom();
		if ( is_wp_error( $scan_data ) ) {
			return false;
		}
		return is_object( $scan_data ) && isset( $scan_data->state ) && 'unavailable' !== $scan_data->state;
	}

	/**
	 * Checks whether the Product is active
	 *
	 * Scan is not actually a module. Activation takes place on WPCOM. So lets consider it active if jetpack is active and has the plan.
	 *
	 * @return boolean
	 */
	public static function is_active() {
		return static::is_jetpack_plugin_active() && static::has_required_plan();
	}

	/**
	 * Activates the product by installing and activating its plugin
	 *
	 * @param bool|WP_Error $current_result Is the result of the top level activation actions. You probably won't do anything if it is an WP_Error.
	 * @return boolean|\WP_Error
	 */
	public static function do_product_specific_activation( $current_result ) {

		$product_activation = parent::do_product_specific_activation( $current_result );

		if ( is_wp_error( $product_activation ) && 'module_activation_failed' === $product_activation->get_error_code() ) {
			// Scan is not a module. There's nothing in the plugin to be activated, so it's ok to fail to activate the module.
			$product_activation = true;
		}

		return $product_activation;
	}

	/**
	 * Checks whether the Jetpack module is active
	 *
	 * Scan is not a module. Nothing needs to be active. Let's always consider it active.
	 *
	 * @return bool
	 */
	public static function is_module_active() {
		return true;
	}

	/**
	 * Return product bundles list
	 * that supports the product.
	 *
	 * @return boolean|array Products bundle list.
	 */
	public static function is_upgradable_by_bundle() {
		return array( 'security' );
	}

	/**
	 * Get the URL the user is taken after activating the product
	 *
	 * @return ?string
	 */
	public static function get_post_activation_url() {
		return ''; // stay in My Jetpack page.
	}

	/**
	 * Get the URL where the user manages the product
	 *
	 * @return ?string
	 */
	public static function get_manage_url() {
		return Redirect::get_url( 'my-jetpack-manage-scan' );
	}

	/**
	 * Get the URL where the user should be redirected after checkout
	 */
	public static function get_post_checkout_url() {
		if ( static::is_jetpack_plugin_active() ) {
			return admin_url( 'admin.php?page=jetpack#/recommendations' );
		}

		// If Jetpack is not active, it means that the user has another standalone plugin active
		// and it follows the `Protect` plugin flow instead of `Scan` so for now it would be safe
		// to return null and let the user go back to the My Jetpack page.
		return null;
	}
}
