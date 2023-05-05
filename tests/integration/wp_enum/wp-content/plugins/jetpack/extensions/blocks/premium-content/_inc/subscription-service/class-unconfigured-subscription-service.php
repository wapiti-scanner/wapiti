<?php
/**
 * The environment does not have a subscription service available.
 * This represents this scenario.
 *
 * @package Automattic\Jetpack\Extensions\Premium_Content
 */

namespace Automattic\Jetpack\Extensions\Premium_Content\Subscription_Service;

use function site_url;
// phpcs:disable

/**
 * Class Unconfigured_Subscription_Service
 *
 * @package Automattic\Jetpack\Extensions\Premium_Content\Subscription_Service
 */
class Unconfigured_Subscription_Service implements Subscription_Service {

	/**
	 * Is always available because it is the fallback.
	 *
	 * @inheritDoc
	 */
	public static function available() {
		return true;
	}

	/**
	 * Function: initialize()
	 *
	 * @inheritDoc
	 */
	public function initialize() {
		// noop.
	}

	/**
	 * No subscription service available, no users can see this content.
	 *
	 * @param array  $valid_plan_ids .
	 * @param string $access_level   .
	 */
	public function visitor_can_view_content( $valid_plan_ids, $access_level ) {
		return false;
	}

	/**
	 * The current visitor would like to obtain access. Where do they go?
	 *
	 * @param string $mode .
	 */
	public function access_url( $mode = 'subscribe' ) {
		return site_url();
	}

}
// phpcs:enable
