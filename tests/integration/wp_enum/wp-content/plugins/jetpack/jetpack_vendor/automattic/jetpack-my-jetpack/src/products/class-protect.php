<?php
/**
 * Protect product
 *
 * @package my-jetpack
 */

namespace Automattic\Jetpack\My_Jetpack\Products;

use Automattic\Jetpack\My_Jetpack\Product;

/**
 * Class responsible for handling the Protect product
 */
class Protect extends Product {

	/**
	 * The product slug
	 *
	 * @var string
	 */
	public static $slug = 'protect';

	/**
	 * The filename (id) of the plugin associated with this product.
	 *
	 * @var string
	 */
	public static $plugin_filename = array(
		'jetpack-protect/jetpack-protect.php',
		'protect/jetpack-protect.php',
		'jetpack-protect-dev/jetpack-protect.php',
	);

	/**
	 * The slug of the plugin associated with this product.
	 *
	 * @var string
	 */
	public static $plugin_slug = 'jetpack-protect';

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
		return __( 'Protect', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product title
	 *
	 * @return string
	 */
	public static function get_title() {
		return __( 'Jetpack Protect', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product description
	 *
	 * @return string
	 */
	public static function get_description() {
		return __( 'Protect your site and scan for security vulnerabilities.', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product long description
	 *
	 * @return string
	 */
	public static function get_long_description() {
		return __( 'Protect your site and scan for security vulnerabilities listed in our database.', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized features list
	 *
	 * @return array Protect features list
	 */
	public static function get_features() {
		return array(
			__( 'Over 20,000 listed vulnerabilities', 'jetpack-my-jetpack' ),
			__( 'Daily automatic scans', 'jetpack-my-jetpack' ),
			__( 'Check plugin and theme version status', 'jetpack-my-jetpack' ),
			__( 'Easy to navigate and use', 'jetpack-my-jetpack' ),
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
	 * Get the URL where the user manages the product
	 *
	 * @return ?string
	 */
	public static function get_manage_url() {
		return admin_url( 'admin.php?page=jetpack-protect' );
	}
}
