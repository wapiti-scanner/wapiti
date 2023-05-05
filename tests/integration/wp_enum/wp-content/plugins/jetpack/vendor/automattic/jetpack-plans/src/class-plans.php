<?php
/**
 * Plans Library
 *
 * Fetch plans data from WordPress.com.
 *
 * This file was copied and adapted from the Jetpack plugin on Mar 2022.
 *
 * @package automattic/jetpack-plans
 */

namespace Automattic\Jetpack;

/**
 * Fetch data about available Plans from WordPress.com
 */
class Plans {
	/**
	 * Get a list of all available plans from WordPress.com
	 *
	 * @since-jetpack 7.7.0
	 *
	 * @return array The plans list
	 */
	public static function get_plans() {
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			if ( ! class_exists( 'Store_Product_List' ) ) {
				require WP_CONTENT_DIR . '/admin-plugins/wpcom-billing/store-product-list.php';
			}

			return Store_Product_List::api_only_get_active_plans_v1_4();
		}

		// We're on Jetpack, so it's safe to use this namespace.
		$request = Automattic\Jetpack\Connection\Client::wpcom_json_api_request_as_user(
			'/plans?_locale=' . get_user_locale(),
			// We're using version 1.5 of the endpoint rather than the default version 2
			// since the latter only returns Jetpack Plans, but we're also interested in
			// WordPress.com plans, for consumers of this method that run on WP.com.
			'1.5',
			array(
				'method'  => 'GET',
				'headers' => array(
					'X-Forwarded-For' => ( new Automattic\Jetpack\Status\Visitor() )->get_ip( true ),
				),
			),
			null,
			'rest'
		);

		$body = wp_remote_retrieve_body( $request );
		if ( 200 === wp_remote_retrieve_response_code( $request ) ) {
			return json_decode( $body );
		} else {
			return $body;
		}
	}

	/**
	 * Get plan information for a plan given its slug
	 *
	 * @since-jetpack 7.7.0
	 *
	 * @param string $plan_slug Plan slug.
	 *
	 * @return object The plan object
	 */
	public static function get_plan( $plan_slug ) {
		$plans = self::get_plans();
		if ( ! is_array( $plans ) ) {
			return;
		}

		foreach ( $plans as $plan ) {
			if ( $plan_slug === $plan->product_slug ) {
				return $plan;
			}
		}
	}
}
