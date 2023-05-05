<?php

namespace WPForms\Helpers;

/**
 * Remote data cache handler.
 *
 * Usage example in `WPForms\Admin\Addons\AddonsCache` and `WPForms\Admin\Builder\TemplatesCache`.
 *
 * @since 1.6.8
 */
abstract class CacheBase {

	/**
	 * Indicates whether the cache was updated during the current run.
	 *
	 * @since 1.6.8
	 *
	 * @var bool
	 */
	protected static $updated = false;

	/**
	 * Settings.
	 *
	 * @since 1.6.8
	 *
	 * @var array
	 */
	protected $settings;

	/**
	 * Determine if the class is allowed to load.
	 *
	 * @since 1.6.8
	 *
	 * @return bool
	 */
	abstract protected function allow_load();

	/**
	 * Initialize.
	 *
	 * @since 1.6.8
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->update_settings();

		// Quit if settings didn't provided.
		if (
			empty( $this->settings['remote_source'] ) ||
			empty( $this->settings['cache_file'] )
		) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Base hooks.
	 *
	 * @since 1.6.8
	 */
	private function hooks() {

		add_action( 'shutdown', [ $this, 'cache_dir_complete' ] );

		if ( empty( $this->settings['update_action'] ) ) {
			return;
		}

		// Schedule recurring updates.
		add_action( 'admin_init', [ $this, 'schedule_update_cache' ] );
		add_action( $this->settings['update_action'], [ $this, 'update_cache' ] );
	}

	/**
	 * Set up settings.
	 *
	 * @since 1.6.8
	 */
	private function update_settings() {

		$default_settings = [

			// Remote source URL.
			// For instance: 'https://wpforms.com/wp-content/addons.json'.
			'remote_source' => '',

			// Cache file.
			// Just file name. For instance: 'addons.json'.
			'cache_file'    => '',

			// Cache time to live in seconds.
			'cache_ttl'     => WEEK_IN_SECONDS,

			// Scheduled update action.
			// For instance: 'wpforms_admin_addons_cache_update'.
			'update_action' => '',
		];

		$this->settings = wp_parse_args( $this->setup(), $default_settings );
	}

	/**
	 * Provide settings.
	 *
	 * @since 1.6.8
	 *
	 * @return array Settings array.
	 */
	abstract protected function setup();

	/**
	 * Get cache directory path.
	 *
	 * @since 1.6.8
	 */
	protected function get_cache_dir() {

		$upload_dir  = wpforms_upload_dir();
		$upload_path = ! empty( $upload_dir['path'] )
			? trailingslashit( wp_normalize_path( $upload_dir['path'] ) )
			: trailingslashit( WP_CONTENT_DIR ) . 'uploads/wpforms/';

		return $upload_path . 'cache/';
	}

	/**
	 * Get cached data.
	 *
	 * @since 1.6.8
	 *
	 * @return array Cached data.
	 */
	public function get_cached() {

		$cache_modified_time = 0;
		$current_time        = time();
		$cache_file          = $this->get_cache_dir() . $this->settings['cache_file'];

		if ( is_file( $cache_file ) && is_readable( $cache_file ) ) {
			clearstatcache( true, $cache_file );
			$cache_modified_time = (int) filemtime( $cache_file );
			$data                = json_decode( file_get_contents( $cache_file ), true );
		}

		if (
			! empty( $data ) &&
			$cache_modified_time + $this->settings['cache_ttl'] > $current_time
		) {
			return $data;
		}

		// This code should execute when the method was called for the first time,
		// Next update_cache() should be executed as scheduled.
		// Also, we will try to update the cache only if the latest unsuccessful try has been 10 (or more) minutes ago.
		if ( $cache_modified_time + 600 < $current_time ) {
			return $this->update_cache();
		}

		return [];
	}

	/**
	 * Update cached data with actual data retrieved from the remote source.
	 *
	 * @since 1.6.8
	 *
	 * @return array
	 */
	public function update_cache() {

		$wpforms_key = 'lite';

		if ( wpforms()->is_pro() ) {
			$wpforms_key = wpforms_get_license_key();
		}

		$request = wp_remote_get(
			add_query_arg( 'tgm-updater-key', $wpforms_key, $this->settings['remote_source'] ),
			[
				'timeout'    => 10,
				'user-agent' => wpforms_get_default_user_agent(),
			]
		);

		if ( is_wp_error( $request ) ) {
			return [];
		}

		$json = wp_remote_retrieve_body( $request );

		if ( empty( $json ) ) {
			return [];
		}

		$data = $this->prepare_cache_data( json_decode( $json, true ) );
		$dir  = $this->get_cache_dir();

		// Just return the data if can't create the cache directory.
		if ( ! wp_mkdir_p( $dir ) ) {
			return $data;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
		file_put_contents(
			$dir . $this->settings['cache_file'],
			wp_json_encode( $data )
		);

		self::$updated = true;

		return $data;
	}

	/**
	 * Schedule updates.
	 *
	 * @since 1.6.8
	 */
	public function schedule_update_cache() {

		// Just skip if not need to register scheduled action.
		if ( empty( $this->settings['update_action'] ) ) {
			return;
		}

		$tasks = wpforms()->get( 'tasks' );

		if ( $tasks->is_scheduled( $this->settings['update_action'] ) !== false ) {
			return;
		}

		$tasks->create( $this->settings['update_action'] )
			  ->recurring( time() + $this->settings['cache_ttl'], $this->settings['cache_ttl'] )
			  ->params()
			  ->register();
	}

	/**
	 * Complete the cache directory.
	 *
	 * @since 1.6.8
	 */
	public function cache_dir_complete() {

		if ( ! self::$updated ) {
			return;
		}

		wpforms_create_upload_dir_htaccess_file();
		wpforms_create_index_html_file( $this->get_cache_dir() );
	}

	/**
	 * Prepare data to store in a local cache.
	 *
	 * @since 1.6.8
	 *
	 * @param array $data Raw data received by the remote request.
	 *
	 * @return array Prepared data for caching.
	 */
	protected function prepare_cache_data( $data ) {

		if ( empty( $data ) || ! is_array( $data ) ) {
			return [];
		}

		return $data;
	}
}
