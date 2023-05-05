<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Handles fetching of the site's plan and products from WordPress.com and caching values locally.
 *
 * Not to be confused with the `Jetpack_Plans` class (in `_inc/lib/plans.php`), which
 * fetches general information about all available plans from WordPress.com, side-effect free.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Client;

/**
 * Provides methods methods for fetching the site's plan and products from WordPress.com.
 */
class Jetpack_Plan {
	/**
	 * A cache variable to hold the active plan for the current request.
	 *
	 * @var array
	 */
	private static $active_plan_cache;

	/**
	 * The name of the option that will store the site's plan.
	 *
	 * @var string
	 */
	const PLAN_OPTION = 'jetpack_active_plan';

	/**
	 * The name of the option that will store the site's products.
	 *
	 * @var string
	 */
	const SITE_PRODUCTS_OPTION = 'jetpack_site_products';

	const PLAN_DATA = array(
		'free'     => array(
			'plans'    => array(
				'jetpack_free',
			),
			'supports' => array(
				'opentable',
				'calendly',
				'send-a-message',
				'whatsapp-button',
				'social-previews',
				'videopress',
				'videopress/video',
				'v6-video-frame-poster',

				'core/video',
				'core/cover',
				'core/audio',
			),
		),
		'personal' => array(
			'plans'    => array(
				'jetpack_personal',
				'jetpack_personal_monthly',
				'personal-bundle',
				'personal-bundle-monthly',
				'personal-bundle-2y',
				'starter-plan',
			),
			'supports' => array(
				'akismet',
				'payments',
				'recurring-payments',
				'premium-content/container',
				'videopress',
			),
		),
		'premium'  => array(
			'plans'    => array(
				'jetpack_premium',
				'jetpack_premium_monthly',
				'value_bundle',
				'value_bundle-monthly',
				'value_bundle-2y',
			),
			'supports' => array(
				'donations',
				'simple-payments',
				'vaultpress',
				'videopress',
				'republicize',
			),
		),
		'security' => array(
			'plans'    => array(
				'jetpack_security_daily',
				'jetpack_security_daily_monthly',
				'jetpack_security_realtime',
				'jetpack_security_realtime_monthly',
				'jetpack_security_t1_yearly',
				'jetpack_security_t1_monthly',
				'jetpack_security_t2_yearly',
				'jetpack_security_t2_monthly',
			),
			'supports' => array(),
		),
		'business' => array(
			'plans'    => array(
				'jetpack_business',
				'jetpack_business_monthly',
				'business-bundle',
				'business-bundle-monthly',
				'business-bundle-2y',
				'ecommerce-bundle',
				'ecommerce-bundle-monthly',
				'ecommerce-bundle-2y',
				'pro-plan',
			),
			'supports' => array(),
		),

		'complete' => array(
			'plans'    => array(
				'jetpack_complete',
				'jetpack_complete_monthly',
				'vip',
			),
			'supports' => array(),
		),
	);

	/**
	 * Given a response to the `/sites/%d` endpoint, will parse the response and attempt to set the
	 * site's plan and products from the response.
	 *
	 * @param array $response The response from `/sites/%d`.
	 * @return bool Was the plan successfully updated?
	 */
	public static function update_from_sites_response( $response ) {
		// Bail if there was an error or malformed response.
		if ( is_wp_error( $response ) || ! is_array( $response ) || ! isset( $response['body'] ) ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		if ( is_wp_error( $body ) ) {
			return false;
		}

		// Decode the results.
		$results = json_decode( $body, true );

		if ( ! is_array( $results ) ) {
			return false;
		}

		if ( isset( $results['products'] ) ) {
			// Store the site's products in an option and return true if updated.
			self::store_data_in_option( self::SITE_PRODUCTS_OPTION, $results['products'] );
		}

		if ( ! isset( $results['plan'] ) ) {
			return false;
		}

		$current_plan = get_option( self::PLAN_OPTION, array() );

		if ( ! empty( $current_plan ) && $current_plan === $results['plan'] ) {
			// Bail if the plans array hasn't changed.
			return false;
		}

		// Store the new plan in an option and return true if updated.
		$result = self::store_data_in_option( self::PLAN_OPTION, $results['plan'] );

		if ( $result ) {
			// Reset the cache since we've just updated the plan.
			self::$active_plan_cache = null;
		}

		return $result;
	}

	/**
	 * Store data in an option.
	 *
	 * @param string $option The name of the option that will store the data.
	 * @param array  $data Data to be store in an option.
	 * @return bool Were the subscriptions successfully updated?
	 */
	private static function store_data_in_option( $option, $data ) {
		$result = update_option( $option, $data, true );

		// If something goes wrong with the update, so delete the current option and then update it.
		if ( ! $result ) {
			delete_option( $option );
			$result = update_option( $option, $data, true );
		}

		return $result;
	}

	/**
	 * Make an API call to WordPress.com for plan status
	 *
	 * @uses Jetpack_Options::get_option()
	 * @uses Client::wpcom_json_api_request_as_blog()
	 * @uses update_option()
	 *
	 * @access public
	 * @static
	 *
	 * @return bool True if plan is updated, false if no update
	 */
	public static function refresh_from_wpcom() {
		// Make the API request.
		$request  = sprintf( '/sites/%d', Jetpack_Options::get_option( 'id' ) );
		$response = Client::wpcom_json_api_request_as_blog( $request, '1.1' );

		return self::update_from_sites_response( $response );
	}

	/**
	 * Get the plan that this Jetpack site is currently using.
	 *
	 * @uses get_option()
	 *
	 * @access public
	 * @static
	 *
	 * @return array Active Jetpack plan details
	 */
	public static function get() {
		// this can be expensive to compute so we cache for the duration of a request.
		if ( is_array( self::$active_plan_cache ) && ! empty( self::$active_plan_cache ) ) {
			return self::$active_plan_cache;
		}

		$plan = get_option( self::PLAN_OPTION, array() );

		// Set the default options.
		$plan = wp_parse_args(
			$plan,
			array(
				'product_slug' => 'jetpack_free',
				'class'        => 'free',
				'features'     => array(
					'active' => array(),
				),
			)
		);

		list( $plan['class'], $supports ) = self::get_class_and_features( $plan['product_slug'] );

		// get available features.
		foreach ( Jetpack::get_available_modules() as $module_slug ) {
			$module = Jetpack::get_module( $module_slug );
			if ( ! isset( $module ) || ! is_array( $module ) ) {
				continue;
			}
			if ( in_array( 'free', $module['plan_classes'], true ) || in_array( $plan['class'], $module['plan_classes'], true ) ) {
				$supports[] = $module_slug;
			}
		}

		$plan['supports'] = $supports;

		self::$active_plan_cache = $plan;

		return $plan;
	}

	/**
	 * Get the site's products.
	 *
	 * @uses get_option()
	 *
	 * @access public
	 * @static
	 *
	 * @return array Active Jetpack products
	 */
	public static function get_products() {
		return get_option( self::SITE_PRODUCTS_OPTION, array() );
	}

	/**
	 * Get the class of plan and a list of features it supports
	 *
	 * @param string $plan_slug The plan that we're interested in.
	 * @return array Two item array, the plan class and the an array of features.
	 */
	private static function get_class_and_features( $plan_slug ) {
		$features = array();
		foreach ( self::PLAN_DATA as $class => $details ) {
			$features = array_merge( $features, $details['supports'] );
			if ( in_array( $plan_slug, $details['plans'], true ) ) {
				return array( $class, $features );
			}
		}
		return array( 'free', self::PLAN_DATA['free']['supports'] );
	}

	/**
	 * Gets the minimum plan slug that supports the given feature
	 *
	 * @param string $feature The name of the feature.
	 * @return string|bool The slug for the minimum plan that supports.
	 *  the feature or false if not found
	 */
	public static function get_minimum_plan_for_feature( $feature ) {
		foreach ( self::PLAN_DATA as $details ) {
			if ( in_array( $feature, $details['supports'], true ) ) {
				return $details['plans'][0];
			}
		}
		return false;
	}

	/**
	 * Determine whether the active plan supports a particular feature
	 *
	 * @uses Jetpack_Plan::get()
	 *
	 * @access public
	 * @static
	 *
	 * @param string $feature The module or feature to check.
	 *
	 * @return bool True if plan supports feature, false if not
	 */
	public static function supports( $feature ) {
		// Hijack the feature eligibility check on WordPress.com sites since they are gated differently.
		$should_wpcom_gate_feature = (
			function_exists( 'wpcom_site_has_feature' ) &&
			function_exists( 'wpcom_feature_exists' ) &&
			wpcom_feature_exists( $feature )
		);
		if ( $should_wpcom_gate_feature ) {
			return wpcom_site_has_feature( $feature );
		}

		// Search product bypasses plan feature check.
		if ( 'search' === $feature && (bool) get_option( 'has_jetpack_search_product' ) ) {
			return true;
		}

		// As of Q3 2021 - a videopress free tier is available to all plans.
		if ( 'videopress' === $feature ) {
			return true;
		}

		$plan = self::get();

		if (
			in_array( $feature, $plan['supports'], true )
			|| in_array( $feature, $plan['features']['active'], true )
		) {
			return true;
		}

		return false;
	}
}
