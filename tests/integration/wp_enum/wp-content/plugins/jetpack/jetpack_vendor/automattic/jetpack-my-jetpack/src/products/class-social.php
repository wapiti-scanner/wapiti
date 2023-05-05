<?php
/**
 * Search product
 *
 * @package my-jetpack
 */

namespace Automattic\Jetpack\My_Jetpack\Products;

use Automattic\Jetpack\My_Jetpack\Hybrid_Product;
use Automattic\Jetpack\My_Jetpack\Wpcom_Products;

/**
 * Class responsible for handling the Social product
 */
class Social extends Hybrid_Product {

	/**
	 * The product slug
	 *
	 * @var string
	 */
	public static $slug = 'social';

	/**
	 * The Jetpack module name
	 *
	 * @var string
	 */
	public static $module_name = 'publicize';

	/**
	 * The slug of the plugin associated with this product.
	 *
	 * @var string
	 */
	public static $plugin_slug = 'jetpack-social';

	/**
	 * Social has a standalone plugin
	 *
	 * @var bool
	 */
	public static $has_standalone_plugin = true;

	/**
	 * The filename (id) of the plugin associated with this product.
	 *
	 * @var string
	 */
	public static $plugin_filename = array(
		'jetpack-social/jetpack-social.php',
		'social/jetpack-social.php',
		'jetpack-social-dev/jetpack-social.php',
	);

	/**
	 * Get the internationalized product name
	 *
	 * @return string
	 */
	public static function get_name() {
		return __( 'Social', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product title
	 *
	 * @return string
	 */
	public static function get_title() {
		return __( 'Jetpack Social', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product description
	 *
	 * @return string
	 */
	public static function get_description() {
		return __( 'Reach your audience on social media', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product long description
	 *
	 * @return string
	 */
	public static function get_long_description() {
		return __( 'Promote your content on social media by automatically publishing when you publish on your site.', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized features list
	 *
	 * @return array Social features list
	 */
	public static function get_features() {
		return array(
			__( 'Post to social networks', 'jetpack-my-jetpack' ),
			__( 'Schedule publishing', 'jetpack-my-jetpack' ),
			__( 'Supports the major social networks', 'jetpack-my-jetpack' ),
		);
	}

	/**
	 * Get the product pricing details
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
	 * @return string
	 */
	public static function get_wpcom_product_slug() {
		return 'jetpack_social';
	}

	/**
	 * Get the URL where the user manages the product.
	 *
	 * If the standalone plugin is active,
	 * it will redirect to the standalone plugin settings page.
	 * Otherwise, it will redirect to the Jetpack settings page.
	 *
	 * @return string
	 */
	public static function get_manage_url() {
		if ( static::is_standalone_plugin_active() ) {
			return admin_url( 'admin.php?page=jetpack-social' );
		}

		return admin_url( 'admin.php?page=jetpack#/settings?term=publicize' );
	}
}
