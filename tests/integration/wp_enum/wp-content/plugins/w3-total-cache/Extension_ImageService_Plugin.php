<?php
/**
 * File: Extension_ImageService_Plugin.php
 *
 * @since 2.2.0
 *
 * @package W3TC
 *
 * phpcs:disable WordPress.WP.CronInterval
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

/**
 * Extension_ImageService_Plugin
 *
 * @since 2.2.0
 */
class Extension_ImageService_Plugin {
	/**
	 * Image Service API object.
	 *
	 * @since 2.2.0
	 *
	 * @static
	 *
	 * @var Extension_ImageService_Api
	 */
	public static $api;

	/**
	 * Add hooks.
	 *
	 * @since 2.2.0
	 * @static
	 */
	public static function wp_loaded() {
		add_action(
			'w3tc_extension_load_admin',
			array(
				'\W3TC\Extension_ImageService_Plugin_Admin',
				'w3tc_extension_load_admin',
			)
		);

		// Cron event handling.
		require_once __DIR__ . '/Extension_ImageService_Cron.php';

		add_action(
			'w3tc_imageservice_cron',
			array(
				'\W3TC\Extension_ImageService_Cron',
				'run',
			)
		);

		add_filter(
			'cron_schedules',
			array(
				'\W3TC\Extension_ImageService_Cron',
				'add_schedule',
			)
		);

		Extension_ImageService_Cron::add_cron();
	}

	/**
	 * Get the Image Service API object.
	 *
	 * @since 2.2.0
	 *
	 * @return Extension_ImageService_Api
	 */
	public static function get_api() {
		if ( is_null( self::$api ) ) {
			require_once __DIR__ . '/Extension_ImageService_Api.php';
			self::$api = new Extension_ImageService_Api();
		}

		return self::$api;
	}
}

w3tc_add_action(
	'wp_loaded',
	array(
		'\W3TC\Extension_ImageService_Plugin',
		'wp_loaded',
	)
);
