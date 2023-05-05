<?php
/**
 * Search product
 *
 * @package my-jetpack
 */

namespace Automattic\Jetpack\My_Jetpack\Products;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Constants;
use Automattic\Jetpack\My_Jetpack\Hybrid_Product;
use Automattic\Jetpack\My_Jetpack\Wpcom_Products;
use Automattic\Jetpack\Search\Module_Control as Search_Module_Control;
use Jetpack_Options;
use WP_Error;

/**
 * Class responsible for handling the Search product
 */
class Search extends Hybrid_Product {
	/**
	 * The product slug
	 *
	 * @var string
	 */
	public static $slug = 'search';

	/**
	 * The Jetpack module name
	 *
	 * @var string
	 */
	public static $module_name = 'search';

	/**
	 * The slug of the plugin associated with this product.
	 *
	 * @var string
	 */
	public static $plugin_slug = 'jetpack-search';

	/**
	 * Search has a standalone plugin
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
		'jetpack-search/jetpack-search.php',
		'search/jetpack-search.php',
		'jetpack-search-dev/jetpack-search.php',
	);

	/**
	 * Search only requires site connection
	 *
	 * @var boolean
	 */
	public static $requires_user_connection = false;

	/**
	 * Get the internationalized product name
	 *
	 * @return string
	 */
	public static function get_name() {
		return __( 'Search', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product title
	 *
	 * @return string
	 */
	public static function get_title() {
		return __( 'Jetpack Search', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product description
	 *
	 * @return string
	 */
	public static function get_description() {
		return __( 'Help them find what they need', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized product long description
	 *
	 * @return string
	 */
	public static function get_long_description() {
		return __( 'Help your site visitors find answers instantly so they keep reading and buying. Great for sites with a lot of content.', 'jetpack-my-jetpack' );
	}

	/**
	 * Get the internationalized features list
	 *
	 * @return array Boost features list
	 */
	public static function get_features() {
		return array(
			__( 'Instant search and indexing', 'jetpack-my-jetpack' ),
			__( 'Powerful filtering', 'jetpack-my-jetpack' ),
			__( 'Supports 38 languages', 'jetpack-my-jetpack' ),
			__( 'Spelling correction', 'jetpack-my-jetpack' ),
		);
	}

	/**
	 * Get the product princing details
	 *
	 * @return array Pricing details
	 */
	public static function get_pricing_for_ui() {
		// Basic pricing info.
		$pricing = array_merge(
			array(
				'available'               => true,
				'trial_available'         => static::has_trial_support(),
				'wpcom_product_slug'      => static::get_wpcom_product_slug(),
				'wpcom_free_product_slug' => static::get_wpcom_free_product_slug(),
			),
			Wpcom_Products::get_product_pricing( static::get_wpcom_product_slug() )
		);

		$record_count   = intval( Search_Stats::estimate_count() );
		$search_pricing = static::get_pricing_from_wpcom( $record_count );

		if ( is_wp_error( $search_pricing ) ) {
			return $pricing;
		}

		$pricing['estimated_record_count'] = $record_count;

		return array_merge( $pricing, $search_pricing );
	}

	/**
	 * Get the WPCOM product slug used to make the purchase
	 *
	 * @return ?string
	 */
	public static function get_wpcom_product_slug() {
		return 'jetpack_search';
	}

	/**
	 * Get the WPCOM free product slug
	 *
	 * @return ?string
	 */
	public static function get_wpcom_free_product_slug() {
		return 'jetpack_search_free';
	}

	/**
	 * Returns true if the new_pricing_202208 is set to not empty in URL for testing purpose, or it's active.
	 */
	public static function is_new_pricing_202208() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		if ( isset( $_GET['new_pricing_202208'] ) && $_GET['new_pricing_202208'] ) {
			return true;
		}

		$record_count   = intval( Search_Stats::estimate_count() );
		$search_pricing = static::get_pricing_from_wpcom( $record_count );
		if ( is_wp_error( $search_pricing ) ) {
			return false;
		}

		return '202208' === $search_pricing['pricing_version'];
	}

	/**
	 * Override status to `needs_purchase_or_free` when status is `needs_purchase`.
	 */
	public static function get_status() {
		$status = parent::get_status();
		return $status;
	}

	/**
	 * Use centralized Search pricing API.
	 *
	 * The function is also used by the search package, as a result it could be called before site connection - i.e. blog token might not be available.
	 *
	 * @param int $record_count Record count to estimate pricing.
	 *
	 * @return array|WP_Error
	 */
	public static function get_pricing_from_wpcom( $record_count ) {
		static $pricings = array();

		if ( isset( $pricings[ $record_count ] ) ) {
			return $pricings[ $record_count ];
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			// For simple sites fetch the response directly.
			$response = Client::wpcom_json_api_request_as_blog(
				sprintf( '/jetpack-search/pricing?record_count=%1$d&locale=%2$s', $record_count, get_user_locale() ),
				'2',
				array( 'timeout' => 5 ),
				null,
				'wpcom'
			);
		} else {
			// For non-simple sites we have to use the wp_remote_get, as connection might not be available.
			$response = wp_remote_get(
				sprintf( Constants::get_constant( 'JETPACK__WPCOM_JSON_API_BASE' ) . '/wpcom/v2/jetpack-search/pricing?record_count=%1$d&locale=%2$s', $record_count, get_user_locale() ),
				array( 'timeout' => 5 )
			);
		}

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'search_pricing_fetch_failed' );
		}

		$body                      = wp_remote_retrieve_body( $response );
		$pricings[ $record_count ] = json_decode( $body, true );
		return $pricings[ $record_count ];
	}

	/**
	 * Hits the wpcom api to check Search status.
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

		$blog_id = Jetpack_Options::get_option( 'id' );

		$response = Client::wpcom_json_api_request_as_blog(
			'/sites/' . $blog_id . '/jetpack-search/plan',
			'2',
			array( 'timeout' => 5 ),
			null,
			'wpcom'
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'search_state_fetch_failed' );
		}

		$body   = wp_remote_retrieve_body( $response );
		$status = json_decode( $body );
		return $status;
	}

	/**
	 * Checks whether the product supports trial or not
	 *
	 * Returns true if it supports. Return false otherwise.
	 *
	 * Free products will always return false.
	 *
	 * @return boolean
	 */
	public static function has_trial_support() {
		return static::is_new_pricing_202208();
	}

	/**
	 * Checks whether the current plan of the site already supports the product
	 *
	 * Returns true if it supports. Return false if a purchase is still required.
	 *
	 * Free products will always return true.
	 *
	 * @return boolean
	 */
	public static function has_required_plan() {
		$search_state = static::get_state_from_wpcom();
		return ! empty( $search_state->supports_search ) || ! empty( $search_state->supports_instant_search );
	}

	/**
	 * Activates the product. Try to enable instant search after the Search module was enabled.
	 *
	 * @param bool|WP_Error $product_activation Is the result of the top level activation actions. You probably won't do anything if it is an WP_Error.
	 * @return bool|WP_Error
	 */
	public static function do_product_specific_activation( $product_activation ) {
		$product_activation = parent::do_product_specific_activation( $product_activation );
		if ( is_wp_error( $product_activation ) ) {
			return $product_activation;
		}

		if ( class_exists( 'Automattic\Jetpack\Search\Module_Control' ) ) {
			( new Search_Module_Control() )->enable_instant_search();
		}

		// we don't want to change the success of the activation if we fail to activate instant search. That's not mandatory.
		return $product_activation;
	}

	/**
	 * Get the URL the user is taken after activating the product
	 *
	 * @return ?string
	 */
	public static function get_post_activation_url() {
		return ''; // stay in My Jetpack page or continue the purchase flow if needed.
	}

	/**
	 * Get the URL where the user manages the product
	 *
	 * @return ?string
	 */
	public static function get_manage_url() {
		return admin_url( 'admin.php?page=jetpack-search' );
	}

}
