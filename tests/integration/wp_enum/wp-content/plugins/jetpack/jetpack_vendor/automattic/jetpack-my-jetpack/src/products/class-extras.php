<?php
/**
 * Extras product
 *
 * @package my-jetpack
 */

namespace Automattic\Jetpack\My_Jetpack\Products;

use Automattic\Jetpack\My_Jetpack\Product;

/**
 * Class responsible for handling the Extras product.
 * Extras, so far, could be considered as Jetpack plugin bridge.
 */
class Extras extends Product {

	/**
	 * The product slug
	 *
	 * @var string
	 */
	public static $slug = 'extras';

	/**
	 * The slug of the plugin associated with this product.
	 * Extras, is in short, Jetpack plugin bridge so far.
	 *
	 * @var string
	 */
	public static $plugin_slug = 'jetpack';

	/**
	 * Whether this product requires a user connection
	 *
	 * @var string
	 */
	public static $requires_user_connection = false;

	/**
	 * Get the internationalized product name
	 *
	 * @return string
	 */
	public static function get_name() {
		return __( 'Extras', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product title
	 *
	 * @return string
	 */
	public static function get_title() {
		return __( 'Jetpack Extras', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product description
	 *
	 * @return string
	 */
	public static function get_description() {
		return __( 'Basic tools for a successful site', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product long description
	 *
	 * @return string
	 */
	public static function get_long_description() {
		return __( "Secure and speed up your site for free with Jetpack's powerful WordPress tools.", 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized features list
	 *
	 * @return array Boost features list
	 */
	public static function get_features() {
		return array(
			__( 'Measure your impact with beautiful stats', 'jetpack-my-jetpack' ),
			__( 'Speed up your site with optimized images', 'jetpack-my-jetpack' ),
			__( 'Protect your site against bot attacks', 'jetpack-my-jetpack' ),
			__( 'Get notifications if your site goes offline', 'jetpack-my-jetpack' ),
			__( 'Enhance your site with dozens of other features', 'jetpack-my-jetpack' ),
		);
	}

	/**
	 * Get the product princing details
	 *
	 * @return array Pricing details
	 */
	public static function get_pricing_for_ui() {
		return array(
			'available' => true,
			'is_free'   => true,
		);
	}

	/**
	 * Checks whether the Product is active.
	 * If Jetpack plugin is active, then Extras will be inactive.
	 *
	 * @return boolean
	 */
	public static function is_active() {
		return static::is_jetpack_plugin_active();
	}

	/**
	 * Checks whether the plugin is installed
	 * If Jetpack plugin is installed, then Extras will be inactive.
	 *
	 * @return boolean
	 */
	public static function is_plugin_installed() {
		return static::is_jetpack_plugin_installed();
	}

	/**
	 * Get the URL where the user manages the product
	 *
	 * @return ?string
	 */
	public static function get_manage_url() {
		return admin_url( 'admin.php?page=jetpack' );
	}

	/**
	 * Activates the Jetpack plugin
	 *
	 * @return null|WP_Error Null on success, WP_Error on invalid file.
	 */
	public static function activate_plugin() {
		return activate_plugin( static::get_installed_plugin_filename( 'jetpack' ) );
	}
}
