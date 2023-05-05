<?php
/**
 * A paywall that exchanges JWT tokens from WordPress.com to allow
 * a current visitor to view content that has been deemed "Premium content".
 *
 * @package Automattic\Jetpack\Extensions\Premium_Content
 */

namespace Automattic\Jetpack\Extensions\Premium_Content\Subscription_Service;

/**
 * Class WPCOM_Token_Subscription_Service
 *
 * @package Automattic\Jetpack\Extensions\Premium_Content\Subscription_Service
 */
class WPCOM_Token_Subscription_Service extends Token_Subscription_Service {

	/**
	 * Is available()
	 *
	 * @inheritDoc
	 */
	public static function available() {
	 // phpcs:ignore ImportDetection.Imports.RequireImports.Symbol
		return defined( 'IS_WPCOM' ) && IS_WPCOM === true;
	}

	/**
	 * Is get_site_id()
	 *
	 * @inheritDoc
	 */
	public function get_site_id() {
		return get_current_blog_id();
	}

	/**
	 * Is get_key()
	 *
	 * @inheritDoc
	 */
	public function get_key() {
	 // phpcs:ignore ImportDetection.Imports.RequireImports.Symbol
		return defined( 'EARN_JWT_SIGNING_KEY' ) ? EARN_JWT_SIGNING_KEY : false;
	}
}
