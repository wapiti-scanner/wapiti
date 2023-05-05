<?php
/**
 * WordAds cron tasks.
 *
 * @package automattic/jetpack
 */

/**
 * WordAds cron tasks
 *
 * @since 4.5.0
 */
class WordAds_Cron {

	/**
	 * Add the actions the cron tasks will use
	 *
	 * @since 4.5.0
	 */
	public function __construct() {
		add_action( 'wordads_cron_status', array( $this, 'update_wordads_status' ) );
	}

	/**
	 * Registered scheduled events on activation
	 *
	 * @since 4.5.0
	 */
	public static function activate() {
		wp_schedule_event( time(), 'daily', 'wordads_cron_status' );
	}

	/**
	 * Clear scheduled hooks on deactivation
	 *
	 * @since 4.5.0
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( 'wordads_cron_status' );
	}

	/**
	 * Grab WordAds status from WP.com API
	 *
	 * @since 4.5.0
	 */
	public static function update_wordads_status() {
		WordAds_API::update_wordads_status_from_api();
	}
}

global $wordads_cron;
$wordads_cron = new WordAds_Cron();
