<?php
/**
 * A class that checks for the existence of email subscriptions for a user.
 *
 * @package automattic/jetpack
 */

/**
 * WPCOM_Email_Subscription_Checker
 */
class WPCOM_Email_Subscription_Checker {

	/**
	 * Checks if a user's site has an email subscription
	 *
	 * @return bool
	 */
	public function has_email() {
		if ( ! function_exists( 'wpcom_site_has_feature' ) ) {
			return false;
		}

		return wpcom_site_has_feature( \WPCOM_Features::EMAIL_SUBSCRIPTION );
	}
}
