<?php
/**
 * A compatibility shim for the sync actions class.
 *
 * @package automattic/jetpack-compat
 */

use Automattic\Jetpack\Sync\Actions;

/**
 * Class Jetpack_Sync_Actions
 *
 * @deprecated Use Automattic\Jetpack\Sync\Actions
 */
class Jetpack_Sync_Actions extends Automattic\Jetpack\Sync\Actions {

	/**
	 * Initializes the class.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::init
	 */
	public static function init() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::init();
	}

	/**
	 * Adds a shutdown sender callback.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::add_sender_shutdown
	 */
	public static function add_sender_shutdown() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::add_sender_shutdown();
	}

	/**
	 * Returns false or true based on whether this class should initialize the sender
	 * in current circumstances.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::should_initialize_sender
	 *
	 * @return Boolean should the object initialize sender?
	 */
	public static function should_initialize_sender() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::should_initialize_sender();
	}

	/**
	 * Returns false or true based on whether sync is allowed.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::sync_allowed
	 *
	 * @return Boolean is sync allowed?
	 */
	public static function sync_allowed() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::sync_allowed();
	}

	/**
	 * Returns false or true based on whether sync via cron is allowed.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::sync_via_cron_allowed
	 *
	 * @return Boolean is sync via cron allowed?
	 */
	public static function sync_via_cron_allowed() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::sync_via_cron_allowed();
	}

	/**
	 * Filters a boolean value that determines whether blocklisted posts should be prevented
	 * from being publicized.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::prevent_publicize_blacklisted_posts
	 *
	 * @param Boolean $should_publicize initial setting value.
	 * @param WP_Post $post the post object.
	 * @return Boolean whether to prevent publicizing.
	 */
	public static function prevent_publicize_blacklisted_posts( $should_publicize, $post ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::prevent_publicize_blacklisted_posts( $should_publicize, $post );
	}

	/**
	 * Set the importing flag to true.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::set_is_importing_true
	 */
	public static function set_is_importing_true() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::set_is_importing_true();
	}

	/**
	 * Send the sync data.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::send_data
	 *
	 * @param Mixed   $data the sync data.
	 * @param String  $codec_name the codec slug.
	 * @param Integer $sent_timestamp the current server timestamp.
	 * @param Integer $queue_id the queue identifier.
	 * @param Integer $checkout_duration time spent retrieving items.
	 * @param Integer $preprocess_duration Time spent converting items into data.
	 * @param Integer $queue_size The current size of the sync queue.
	 * @param string  $buffer_id The ID of the Queue buffer checked out for processing.
	 *
	 * @return WP_Response the response object.
	 */
	public static function send_data( $data, $codec_name, $sent_timestamp, $queue_id, $checkout_duration, $preprocess_duration, $queue_size = null, $buffer_id = null ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::send_data( $data, $codec_name, $sent_timestamp, $queue_id, $checkout_duration, $preprocess_duration, $queue_size, $buffer_id );
	}

	/**
	 * Commence initial sync.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::do_initial_sync
	 */
	public static function do_initial_sync() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::do_initial_sync();
	}

	/**
	 * Commence full sync.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::do_full_sync
	 *
	 * @param array $modules the modules list.
	 * @return Boolean whether the sync was initialized.
	 */
	public static function do_full_sync( $modules = null ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::do_full_sync( $modules );
	}

	/**
	 * Schedule cron sessions.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::jetpack_cron_schedule
	 *
	 * @param array $schedules the schedules to add.
	 */
	public static function jetpack_cron_schedule( $schedules ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::jetpack_cron_schedule( $schedules );
	}

	/**
	 * Commence cron sync.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::do_cron_sync
	 */
	public static function do_cron_sync() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::do_cron_sync();
	}

	/**
	 * Commence cron full sync.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::do_cron_full_sync
	 */
	public static function do_cron_full_sync() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::do_cron_full_sync();
	}

	/**
	 * Commence cron sync of a specific type of object.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::do_cron_sync_by_type
	 *
	 * @param array $type the type of object to sync.
	 */
	public static function do_cron_sync_by_type( $type ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::do_cron_sync_by_type();
	}

	/**
	 * Initalize the listener of the object.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::initialize_listener
	 */
	public static function initialize_listener() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::initialize_listener();
	}

	/**
	 * Initalize the sender of the object.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::initialize_sender
	 */
	public static function initialize_sender() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::initialize_sender();
	}

	/**
	 * Initalize the woocommerce listeners.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::initialize_woocommerce
	 */
	public static function initialize_woocommerce() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::initialize_woocommerce();
	}

	/**
	 * Add the woocommerce sync module.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::add_woocommerce_sync_module
	 *
	 * @param array $sync_modules an array of modules.
	 */
	public static function add_woocommerce_sync_module( $sync_modules ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::add_woocommerce_sync_module( $sync_modules );
	}

	/**
	 * Initalize the WP Super Cache listener.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::initialize_wp_super_cache
	 */
	public static function initialize_wp_super_cache() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::initialize_wp_super_cache();
	}

	/**
	 * Add the WP Super Cache sync module.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::add_wp_super_cache_sync_module
	 *
	 * @param array $sync_modules the list to be amended.
	 */
	public static function add_wp_super_cache_sync_module( $sync_modules ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::add_wp_super_cache_sync_module( $sync_modules );
	}

	/**
	 * Sanitizes the filtered sync cron schedule.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::sanitize_filtered_sync_cron_schedule
	 *
	 * @param String $schedule the cron schedule to sanitize.
	 * @return String sanitized cron schedule.
	 */
	public static function sanitize_filtered_sync_cron_schedule( $schedule ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::sanitize_filtered_sync_cron_schedule( $schedule );
	}

	/**
	 * Returns the time offset for a the start schedule.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::get_start_time_offset
	 *
	 * @param String $schedule the schedule string.
	 * @param String $hook hook slug.
	 * @return Integer start time offset.
	 */
	public static function get_start_time_offset( $schedule = '', $hook = '' ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::get_start_time_offset( $schedule, $hook );
	}

	/**
	 * If needed, schedule a cron sync.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::maybe_schedule_sync_cron
	 *
	 * @param String $schedule the schedule string.
	 * @param String $hook hook slug.
	 */
	public static function maybe_schedule_sync_cron( $schedule, $hook ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::maybe_schedule_sync_cron( $schedule, $hook );
	}

	/**
	 * Clears cron jobs scheduled for sync.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::clear_sync_cron_jobs
	 */
	public static function clear_sync_cron_jobs() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::clear_sync_cron_jobs();
	}

	/**
	 * Initialize cron jobs for sync.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::init_sync_cron_jobs
	 */
	public static function init_sync_cron_jobs() {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::init_sync_cron_jobs();
	}

	/**
	 * Cleans up schedules on plugin upgrade.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::cleanup_on_upgrade
	 *
	 * @param String $new_version the new version.
	 * @param String $old_version the old version.
	 */
	public static function cleanup_on_upgrade( $new_version = null, $old_version = null ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::cleanup_on_upgrade( $new_version, $old_version );
	}

	/**
	 * Clears cron jobs scheduled for sync.
	 *
	 * @deprecated Automattic\Jetpack\Sync\Actions::get_sync_status
	 *
	 * @param array $fields sync fields to get status of.
	 */
	public static function get_sync_status( $fields = null ) {
		_deprecated_function( __METHOD__, 'jetpack-7.5', 'Automattic\Jetpack\Sync\Actions' );

		return Actions::get_sync_status( $fields );
	}
}
