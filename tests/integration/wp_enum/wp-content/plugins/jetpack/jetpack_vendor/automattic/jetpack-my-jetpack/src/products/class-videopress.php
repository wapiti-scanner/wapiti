<?php
/**
 * VideoPress product
 *
 * @package my-jetpack
 */

namespace Automattic\Jetpack\My_Jetpack\Products;

use Automattic\Jetpack\My_Jetpack\Hybrid_Product;
use Automattic\Jetpack\My_Jetpack\Wpcom_Products;

/**
 * Class responsible for handling the VideoPress product
 */
class Videopress extends Hybrid_Product {

	/**
	 * The product slug
	 *
	 * @var string
	 */
	public static $slug = 'videopress';

	/**
	 * The Jetpack module name
	 *
	 * @var string
	 */
	public static $module_name = 'videopress';

	/**
	 * The slug of the plugin associated with this product.
	 *
	 * @var string
	 */
	public static $plugin_slug = 'jetpack-videopress';

	/**
	 * The filename (id) of the plugin associated with this product.
	 *
	 * @var string
	 */
	public static $plugin_filename = array(
		'jetpack-videopress/jetpack-videopress.php',
		'videopress/jetpack-videopress.php',
		'jetpack-videopress-dev/jetpack-videopress.php',
	);

	/**
	 * Search only requires site connection
	 *
	 * @var boolean
	 */
	public static $requires_user_connection = true;

	/**
	 * VideoPress has a standalone plugin
	 *
	 * @var bool
	 */
	public static $has_standalone_plugin = true;

	/**
	 * Get the internationalized product name
	 *
	 * @return string
	 */
	public static function get_name() {
		return __( 'VideoPress', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product title
	 *
	 * @return string
	 */
	public static function get_title() {
		return __( 'Jetpack VideoPress', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product description
	 *
	 * @return string
	 */
	public static function get_description() {
		return __( 'High quality, ad-free video', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product long description
	 *
	 * @return string
	 */
	public static function get_long_description() {
		return __( 'High-quality, ad-free video built specifically for WordPress.', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized features list
	 *
	 * @return array Boost features list
	 */
	public static function get_features() {
		return array(
			_x( '1TB of storage', 'VideoPress Product Feature', 'jetpack-my-jetpack' ),
			_x( 'Built into WordPress editor', 'VideoPress Product Feature', 'jetpack-my-jetpack' ),
			_x( 'Ad-free and customizable player', 'VideoPress Product Feature', 'jetpack-my-jetpack' ),
			_x( 'Unlimited users', 'VideoPress Product Feature', 'jetpack-my-jetpack' ),
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
		return 'jetpack_videopress';
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
		if ( method_exists( 'Automattic\Jetpack\VideoPress\Initializer', 'should_initialize_admin_ui' ) && \Automattic\Jetpack\VideoPress\Initializer::should_initialize_admin_ui() ) {
			return \Automattic\Jetpack\VideoPress\Admin_UI::get_admin_page_url();
		} else {
			return admin_url( 'admin.php?page=jetpack#/settings?term=videopress' );
		}
	}

}
