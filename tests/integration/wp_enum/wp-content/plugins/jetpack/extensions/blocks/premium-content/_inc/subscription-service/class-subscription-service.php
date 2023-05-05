<?php
/**
 * The Subscription Service represents the entity responsible for making sure a visitor
 * can see blocks that are considered premium content.
 *
 * If a visitor is not allowed to see they need to be given a way gain access.
 *
 * It is assumed that it will be a monetary exchange but that is up to the host
 * that brokers the content exchange.
 *
 * @package Automattic\Jetpack\Extensions\Premium_Content;
 */

namespace Automattic\Jetpack\Extensions\Premium_Content\Subscription_Service;

interface Subscription_Service {

	/**
	 * The subscription service can be used.
	 *
	 * @return boolean
	 */
	public static function available();

	/**
	 * Allows a Subscription Service to setup anything it needs to provide its features.
	 *
	 * This is called during an `init` action hook callback.
	 *
	 * Examples of things a Service may want to do here:
	 *  - Determine a visitor is arriving with a new token to unlock content and
	 *    store the token for future browsing (e.g. in a cookie)
	 *  - Set up WP-API endpoints necessary for the function to work
	 *    - Token refreshes
	 *
	 * @return void
	 */
	public function initialize();

	/**
	 * Given a token (this could be from a cookie, a querystring, or some other means)
	 * can the visitor see the premium content?
	 *
	 * @param array  $valid_plan_ids .
	 * @param string $access_level   .
	 *
	 * @return boolean
	 */
	public function visitor_can_view_content( $valid_plan_ids, $access_level );

	/**
	 * The current visitor would like to obtain access. Where do they go?
	 *
	 * @param string $mode .
	 * @return string
	 */
	public function access_url( $mode = 'subscribe' );
}
