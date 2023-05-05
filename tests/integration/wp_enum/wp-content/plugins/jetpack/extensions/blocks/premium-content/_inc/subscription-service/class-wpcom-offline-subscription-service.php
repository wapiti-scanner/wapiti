<?php
/**
 * This subscription service is used when a subscriber is offline and a token is not available.
 *
 * @package Automattic\Jetpack\Extensions\Premium_Content
 */

namespace Automattic\Jetpack\Extensions\Premium_Content\Subscription_Service;

/**
 * Class WPCOM_Offline_Subscription_Service
 * This subscription service is used when a subscriber is offline and a token is not available.
 * This subscription service will be used when sending emails to subscribers
 *
 * @package Automattic\Jetpack\Extensions\Premium_Content\Subscription_Service
 */
class WPCOM_Offline_Subscription_Service extends WPCOM_Online_Subscription_Service {

	/**
	 * Is available()
	 *
	 * @return bool
	 */
	public static function available() {
		// Return available if the user is logged in and we are on WPCOM.
		return false;
	}

	/**
	 * Check if the subscriber can receive the newsletter.
	 * This is the only method where is user does not need to be logged in.
	 *
	 * @param int $user_id User id.
	 * @param int $post_id Post id.
	 *
	 * @return bool
	 * @throws \Exception Throws an exception when used outside of WPCOM.
	 */
	public function subscriber_can_receive_post_by_mail( $user_id, $post_id ) {

		if ( 0 === $user_id || empty( $user_id ) ) {
			// Email cannot be sent to non-users
			return false;
		}

		$previous_user = wp_get_current_user();
		wp_set_current_user( $user_id );

		$access_level       = get_post_meta( $post_id, '_jetpack_newsletter_access', true );
		$valid_plan_ids     = \Jetpack_Memberships::get_all_plans_id_jetpack_recurring_payments();
		$is_blog_subscriber = true; // it is a subscriber as this is used in async when lopping through subscribers...
		$allowed            = $this->user_can_view_content( $valid_plan_ids, $access_level, $is_blog_subscriber, $post_id );

		wp_set_current_user( $previous_user->ID );

		return $allowed;
	}
}
