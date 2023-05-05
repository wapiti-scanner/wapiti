<?php
/**
 * Security product
 *
 * @package my-jetpack
 */

namespace Automattic\Jetpack\My_Jetpack\Products;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\My_Jetpack\Module_Product;
use Automattic\Jetpack\My_Jetpack\Wpcom_Products;
use Jetpack_Options;
use WP_Error;

/**
 * Class responsible for handling the Security product
 */
class Security extends Module_Product {

	/**
	 * The product slug
	 *
	 * @var string
	 */
	public static $slug = 'security';

	/**
	 * The Jetpack module name
	 *
	 * @var string
	 */
	public static $module_name = 'security';

	/**
	 * Get the internationalized product name
	 *
	 * @return string
	 */
	public static function get_name() {
		return _x( 'Security', 'Jetpack product name', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product title
	 *
	 * @return string
	 */
	public static function get_title() {
		return _x( 'Security', 'Jetpack product name', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product description
	 *
	 * @return string
	 */
	public static function get_description() {
		return __( 'Comprehensive site security, including VaultPress Backup, Scan, and Akismet Anti-spam.', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product long description
	 *
	 * @return string
	 */
	public static function get_long_description() {
		return __( 'Comprehensive site security, including VaultPress Backup, Scan, and Akismet Anti-spam.', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized features list
	 *
	 * @return array Boost features list
	 */
	public static function get_features() {
		return array(
			_x( 'Real-time cloud backups with 10GB storage', 'Security Product Feature', 'jetpack-my-jetpack' ),
			_x( 'Automated real-time malware scan', 'Security Product Feature', 'jetpack-my-jetpack' ),
			_x( 'One-click fixes for most threats', 'Security Product Feature', 'jetpack-my-jetpack' ),
			_x( 'Comment & form spam protection', 'Security Product Feature', 'jetpack-my-jetpack' ),
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
		return 'jetpack_security_t1_yearly';
	}

	/**
	 * Checks whether the Jetpack module is active
	 *
	 * This is a bundle and not a product. We should not use this information for anything
	 *
	 * @return bool
	 */
	public static function is_module_active() {
		return false;
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
			// A bundle is not a module. There's nothing in the plugin to be activated, so it's ok to fail to activate the module.
			$product_activation = true;
		}

		// At this point, Jetpack plugin is installed. Let's activate each individual product.
		$activation = Anti_Spam::activate();
		if ( is_wp_error( $activation ) ) {
			return $activation;
		}

		$activation = Backup::activate();
		if ( is_wp_error( $activation ) ) {
			return $activation;
		}

		$activation = Scan::activate();
		if ( is_wp_error( $activation ) ) {
			return $activation;
		}

		return $activation;
	}

	/**
	 * Checks whether the Product is active
	 *
	 * Security is a bundle and not a module. Activation takes place on WPCOM. So lets consider it active if jetpack is active and has the plan.
	 *
	 * @return boolean
	 */
	public static function is_active() {
		return static::is_jetpack_plugin_active() && static::has_required_plan();
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

		$response = Client::wpcom_json_api_request_as_blog(
			sprintf( '/sites/%d/purchases', $site_id ),
			'1.1',
			array(
				'method' => 'GET',
			)
		);
		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'purchases_state_fetch_failed' );
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
		$purchases_data = static::get_state_from_wpcom();
		if ( is_wp_error( $purchases_data ) ) {
			return false;
		}
		if ( is_array( $purchases_data ) && ! empty( $purchases_data ) ) {
			foreach ( $purchases_data as $purchase ) {
				if (
					0 === strpos( $purchase->product_slug, 'jetpack_security' ) ||
					0 === strpos( $purchase->product_slug, 'jetpack_complete' )
				) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Checks whether product is a bundle.
	 *
	 * @return boolean True
	 */
	public static function is_bundle_product() {
		return true;
	}

	/**
	 * Return all the products it contains.
	 *
	 * @return Array Product slugs
	 */
	public static function get_supported_products() {
		return array( 'backup', 'scan', 'anti-spam' );
	}

	/**
	 * Get the URL where the user manages the product
	 *
	 * @return ?string
	 */
	public static function get_manage_url() {
		return '';
	}
}
