<?php // phpcs:ignore WordPress.Files.FileName
/**
 * VideoPress cron scheduler.
 *
 * @package automattic/jetpack
 */

/**
 * VideoPress Cron Scheduler.
 */
class VideoPress_Scheduler {

	/**
	 * The name of the function used to run the cleanup cron.
	 */
	const CLEANUP_CRON_METHOD = 'videopress_cleanup_media_library';

	/**
	 * Singleton instance.
	 *
	 * @var VideoPress_Scheduler $instance A VideoPress_Scheduler singleton instance (default null)
	 **/
	private static $instance = null;

	/**
	 * A list of all of the crons that are to be activated, along with their interval timings.
	 *
	 * @var array
	 */
	protected $crons = array(
		// phpcs:ignore Squiz.PHP.CommentedOutCode.Found
	// 'cleanup' => array(
	// 'method' => self::CLEANUP_CRON_METHOD,
	// 'interval' => 'minutes_30',
	// ),
	);

	/**
	 * Private VideoPress_Scheduler constructor.
	 *
	 * Use the VideoPress_Scheduler::init() method to get an instance.
	 */
	private function __construct() {
		add_filter( 'cron_schedules', array( $this, 'add_30_minute_cron_interval' ) );

		// Activate the cleanup cron if videopress is enabled, jetpack is activated, or jetpack is updated.
		add_action( 'jetpack_activate_module_videopress', array( $this, 'activate_all_crons' ) );
		add_action( 'updating_jetpack_version', array( $this, 'activate_all_crons' ) );
		add_action( 'activated_plugin', array( $this, 'activate_crons_on_jetpack_activation' ) );

		// Deactivate the cron if either videopress is disabled or Jetpack is disabled.
		add_action( 'jetpack_deactivate_module_videopress', array( $this, 'deactivate_all_crons' ) );
		register_deactivation_hook( plugin_basename( JETPACK__PLUGIN_FILE ), array( $this, 'deactivate_all_crons' ) );
	}

	/**
	 * Initialize the VideoPress_Scheduler and get back a singleton instance.
	 *
	 * @return VideoPress_Scheduler
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new VideoPress_Scheduler();
		}

		return self::$instance;
	}

	/**
	 * Adds 30 minute running interval to the cron schedules.
	 *
	 * @param array $current_schedules Currently defined schedules list.
	 *
	 * @return array
	 */
	public function add_30_minute_cron_interval( $current_schedules ) {

		// Only add the 30 minute interval if it wasn't already set.
		if ( ! isset( $current_schedules['minutes_30'] ) ) {
			$current_schedules['minutes_30'] = array(
				'interval' => 30 * MINUTE_IN_SECONDS,
				'display'  => 'Every 30 minutes',
			);
		}

		return $current_schedules;
	}

	/**
	 * Activate a single cron
	 *
	 * @param string $cron_name The name of the cron to activate.
	 *
	 * @return bool
	 */
	public function activate_cron( $cron_name ) {

		if ( ! $this->is_cron_valid( $cron_name ) ) {
			return false;
		}

		if ( ! $this->check_cron( $cron_name ) ) {
			wp_schedule_event( time(), $this->crons[ $cron_name ]['interval'], $this->crons[ $cron_name ]['method'] );
		}
	}

	/**
	 * Activates widget update cron task.
	 */
	public function activate_all_crons() {

		if ( ! Jetpack::is_module_active( 'videopress' ) ) {
			return false;
		}

		foreach ( $this->crons as $cron_name => $cron ) {
			if ( ! $this->check_cron( $cron_name ) ) {
				wp_schedule_event( time(), $cron['interval'], $cron['method'] );
			}
		}
	}

	/**
	 * Only activate the crons if it is Jetpack that was activated.
	 *
	 * @param string $plugin_file_name The name of the plugin that was activated.
	 */
	public function activate_crons_on_jetpack_activation( $plugin_file_name ) {

		if ( plugin_basename( JETPACK__PLUGIN_FILE ) === $plugin_file_name ) {
			$this->activate_all_crons();
		}
	}

	/**
	 * Deactivates any crons associated with the VideoPress module.
	 *
	 * @param string $cron_name Name of the cron to deactivate.
	 *
	 * @return bool
	 */
	public function deactivate_cron( $cron_name ) {

		if ( ! $this->is_cron_valid( $cron_name ) ) {
			return false;
		}

		$next_scheduled_time = $this->check_cron( $cron_name );
		wp_unschedule_event( $next_scheduled_time, $this->crons[ $cron_name ]['method'] );

		return true;
	}

	/**
	 * Deactivates any crons associated with the VideoPress module..
	 */
	public function deactivate_all_crons() {

		foreach ( $this->crons as $cron_name => $cron ) {
			$this->deactivate_cron( $cron_name );
		}
	}

	/**
	 * Is the given cron job currently active?
	 *
	 * If so, return when it will next run,
	 *
	 * @param string $cron_name Cron job name.
	 *
	 * @return int|bool Timestamp of the next run time OR false.
	 */
	public function check_cron( $cron_name ) {
		if ( ! $this->is_cron_valid( $cron_name ) ) {
			return false;
		}

		return wp_next_scheduled( $this->crons[ $cron_name ]['method'] );
	}

	/**
	 * Check that the given cron job name is valid.
	 *
	 * @param string $cron_name Cron job name.
	 *
	 * @return bool
	 */
	public function is_cron_valid( $cron_name ) {

		if ( ! isset( $this->crons[ $cron_name ]['method'] ) || ! isset( $this->crons[ $cron_name ]['interval'] ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Get a list of all of the crons that are available.
	 *
	 * @return array
	 */
	public function get_crons() {
		return $this->crons;
	}
}
