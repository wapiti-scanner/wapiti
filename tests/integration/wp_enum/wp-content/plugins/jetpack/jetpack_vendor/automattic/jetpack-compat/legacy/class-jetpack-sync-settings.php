<?php
/**
 * Legacy/deprecated Sync Setting getter and setter.
 *
 * @package automattic/jetpack-sync
 */

use Automattic\Jetpack\Sync\Settings;

/**
 * Class Jetpack_Sync_Settings
 *
 * @deprecated Use Automattic\Jetpack\Sync\Settings
 */
class Jetpack_Sync_Settings {

	/**
	 * Return all settings
	 *
	 * @deprecated See Automattic/Jetpack/Sync/Settings
	 *
	 * @return array All Sync Settings.
	 */
	public static function get_settings() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::get_settings();
	}

	/**
	 * Return a single setting.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @param string $setting Setting to return.
	 *
	 * @return mixed Value of setting.
	 */
	public static function get_setting( $setting ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::get_setting( $setting );
	}

	/**
	 * Update a sync setting
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @param mixed $new_settings New setting to set.
	 */
	public static function update_settings( $new_settings ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		Settings::update_settings( $new_settings );
	}

	/**
	 * Return is_network_setting result.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @param string $setting Setting to check.
	 *
	 * @return bool
	 */
	public static function is_network_setting( $setting ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::is_network_setting( $setting );
	}

	/**
	 * Return blocklisted post types SQL.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 */
	public static function get_blacklisted_post_types_sql() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::get_blacklisted_post_types_sql();
	}

	/**
	 * Return allowed post meta SQL.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @return string
	 */
	public static function get_whitelisted_post_meta_sql() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::get_whitelisted_post_meta_sql();
	}

	/**
	 * Return allowed comment meta SQL
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 */
	public static function get_whitelisted_comment_meta_sql() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::get_whitelisted_comment_meta_sql();
	}

	/**
	 * Return get_comments_filter_sql
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 */
	public static function get_comments_filter_sql() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::get_comments_filter_sql();
	}

	/**
	 * Result data.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 */
	public static function reset_data() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		Settings::reset_data();
	}

	/**
	 * Set importing status.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @param mixed $is_importing Value to set.
	 */
	public static function set_importing( $is_importing ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		Settings::set_importing( $is_importing );
	}

	/**
	 * Return is_importing status.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @return bool
	 */
	public static function is_importing() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::is_importing();
	}

	/**
	 * Return is_sync_enabled status.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @return bool
	 */
	public static function is_sync_enabled() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::is_sync_enabled();
	}

	/**
	 * Set cron status.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @param mixed $is_doing_cron Value to set.
	 */
	public static function set_doing_cron( $is_doing_cron ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		Settings::set_doing_cron( $is_doing_cron );
	}

	/**
	 * Return is_doing_cron status.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @return bool
	 */
	public static function is_doing_cron() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::is_doing_cron();
	}

	/**
	 * Return is_syncing status.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @return bool
	 */
	public static function is_syncing() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::is_syncing();
	}

	/**
	 * Set "is syncing" status.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @param mixed $is_syncing Is syncing value.
	 */
	public static function set_is_syncing( $is_syncing ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		Settings::set_is_syncing( $is_syncing );
	}

	/**
	 * Return is_sending status.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @return bool
	 */
	public static function is_sending() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		return Settings::is_sending();
	}

	/**
	 * Set "is sending" status.
	 *
	 * @deprecated See Automattic\Jetpack\Sync\Settings
	 *
	 * @param mixed $is_sending Is sending value.
	 */
	public static function set_is_sending( $is_sending ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Settings' );
		Settings::set_is_sending( $is_sending );
	}

}
