<?php
/**
 * Class for manipulating products
 *
 * @package automattic/my-jetpack
 */

namespace Automattic\Jetpack\My_Jetpack;

/**
 * A class for everything related to product handling in My Jetpack
 */
class Products {

	/**
	 * Get the list of Products classes
	 *
	 * Here's where all the existing Products are registered
	 *
	 * @throws \Exception If the result of a filter has invalid classes.
	 * @return array List of class names
	 */
	public static function get_products_classes() {
		$classes = array(
			'anti-spam'  => Products\Anti_Spam::class,
			'backup'     => Products\Backup::class,
			'boost'      => Products\Boost::class,
			'crm'        => Products\Crm::class,
			'extras'     => Products\Extras::class,
			'scan'       => Products\Scan::class,
			'search'     => Products\Search::class,
			'social'     => Products\Social::class,
			'security'   => Products\Security::class,
			'protect'    => Products\Protect::class,
			'videopress' => Products\Videopress::class,
		);

		/**
		 * This filter allows plugin to override the Product class of a given product. The new class must be a child class of the default one declared in My Jetpack
		 *
		 * For example, a stand-alone plugin could overwrite its product class to control specific behavior of the product in the My Jetpack page after it is active without having to commit changes to the My Jetpack package:
		 *
		 * add_filter( 'my_jetpack_products_classes', function( $classes ) {
		 *  $classes['my_plugin'] = 'My_Plugin'; // a class that extends the original one declared in the My Jetpack package.
		 *  return $classes
		 * } );
		 *
		 * @param array $classes An array where the keys are the product slugs and the values are the class names.
		 */
		$final_classes = apply_filters( 'my_jetpack_products_classes', $classes );

		// Check that the classes are still child of the same original classes.
		foreach ( (array) $final_classes as $slug => $final_class ) {
			if ( $final_class === $classes[ $slug ] ) {
				continue;
			}
			if ( ! class_exists( $final_class ) || ! is_subclass_of( $final_class, $classes[ $slug ] ) ) {
				throw new \Exception( 'You can only overwrite a Product class with a child of the original class.' );
			}
		}

		return $final_classes;
	}

	/**
	 * Product data
	 *
	 * @return array Jetpack products on the site and their availability.
	 */
	public static function get_products() {
		$products = array();
		foreach ( self::get_products_classes() as $class ) {
			$product_slug              = $class::$slug;
			$products[ $product_slug ] = $class::get_info();
		}
		return $products;
	}

	/**
	 * Get one product data by its slug
	 *
	 * @param string $product_slug The product slug.
	 *
	 * @return ?array
	 */
	public static function get_product( $product_slug ) {
		$classes = self::get_products_classes();
		if ( isset( $classes[ $product_slug ] ) ) {
			return $classes[ $product_slug ]::get_info();
		}
	}

	/**
	 * Get one product Class name
	 *
	 * @param string $product_slug The product slug.
	 *
	 * @return ?string
	 */
	public static function get_product_class( $product_slug ) {
		$classes = self::get_products_classes();
		if ( isset( $classes[ $product_slug ] ) ) {
			return $classes[ $product_slug ];
		}
	}

	/**
	 * Return product slugs list.
	 *
	 * @return array Product slugs array.
	 */
	public static function get_products_slugs() {
		return array_keys( self::get_products_classes() );
	}

	/**
	 * Gets the json schema for the product data
	 *
	 * @return array
	 */
	public static function get_product_data_schema() {
		return array(
			'title'      => 'The requested product data',
			'type'       => 'object',
			'properties' => array(
				'product'     => array(
					'description'       => __( 'Product slug', 'jetpack-my-jetpack' ),
					'type'              => 'string',
					'enum'              => __CLASS__ . '::get_product_slugs',
					'required'          => false,
					'validate_callback' => __CLASS__ . '::check_product_argument',
				),
				'action'      => array(
					'description'       => __( 'Production action to execute', 'jetpack-my-jetpack' ),
					'type'              => 'string',
					'enum'              => array( 'activate', 'deactivate' ),
					'required'          => false,
					'validate_callback' => __CLASS__ . '::check_product_argument',
				),
				'slug'        => array(
					'title' => 'The product slug',
					'type'  => 'string',
				),
				'name'        => array(
					'title' => 'The product name',
					'type'  => 'string',
				),
				'description' => array(
					'title' => 'The product description',
					'type'  => 'string',
				),
				'status'      => array(
					'title' => 'The product status',
					'type'  => 'string',
					'enum'  => array( 'active', 'inactive', 'plugin_absent', 'needs_purchase', 'needs_purchase_or_free', 'error' ),
				),
				'class'       => array(
					'title' => 'The product class handler',
					'type'  => 'string',
				),
			),
		);
	}

	/**
	 * Extend actions links for plugins
	 * tied to the Products.
	 */
	public static function extend_plugins_action_links() {
		$products = array(
			'backup',
			'boost',
			'crm',
			'videopress', // we use videopress here to add the plugin action to the Jetpack plugin itself
		);
		foreach ( $products as $product ) {
			$class_name = self::get_product_class( $product );
			$class_name::extend_plugin_action_links();
		}
	}

}
