<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Status;

/**
 * Display a list of recent posts from a WordPress.com or Jetpack-enabled blog.
 */
class Jetpack_Display_Posts_Widget extends Jetpack_Display_Posts_Widget__Base {
	/**
	 * Widget options key prefix.
	 *
	 * @var string
	 */
	public $widget_options_key_prefix = 'display_posts_site_data_';

	/**
	 * The name of the cron that will update widget data.
	 *
	 * @var string
	 */
	public static $cron_name = 'jetpack_display_posts_widget_cron_update';

	// DATA STORE.

	/**
	 * Gets blog data from the cache.
	 *
	 * @param string $site Site.
	 *
	 * @return array|WP_Error
	 */
	public function get_blog_data( $site ) {
		// Load from cache, if nothing return an error.
		$site_hash = $this->get_site_hash( $site );

		$cached_data = $this->wp_get_option( $this->widget_options_key_prefix . $site_hash );

		/**
		 * If the cache is empty, return an empty_cache error.
		 */
		if ( false === $cached_data ) {
			return new WP_Error(
				'empty_cache',
				__( 'Information about this blog is currently being retrieved.', 'jetpack' )
			);
		}

		return $cached_data;
	}

	/**
	 * Update a widget instance.
	 *
	 * @param string $site The site to fetch the latest data for.
	 *
	 * @return array - the new data
	 */
	public function update_instance( $site ) {

		/**
		 * Fetch current information for a site.
		 */
		$site_hash = $this->get_site_hash( $site );

		$option_key = $this->widget_options_key_prefix . $site_hash;

		$instance_data = $this->wp_get_option( $option_key );

		/**
		 * Fetch blog data and save it in $instance_data.
		 */
		$new_data = $this->fetch_blog_data( $site, $instance_data );

		/**
		 * If the option doesn't exist yet - create a new option
		 */
		if ( false === $instance_data ) {
			$this->wp_add_option( $option_key, $new_data );
		} else {
			$this->wp_update_option( $option_key, $new_data );
		}

		return $new_data;
	}

	// WIDGET API.

	/**
	 * Widget update function.
	 *
	 * @param array $new_instance New instance widget settings.
	 * @param array $old_instance Old instance widget settings.
	 */
	public function update( $new_instance, $old_instance ) {
		$instance = parent::update( $new_instance, $old_instance );

		/**
		 * Forcefully activate the update cron when saving widget instance.
		 *
		 * So we can be sure that it will be running later.
		 */
		$this->activate_cron();

		return $instance;
	}

	// CRON.

	/**
	 * Activates widget update cron task.
	 */
	public static function activate_cron() {
		if ( ! wp_next_scheduled( self::$cron_name ) ) {
			wp_schedule_event( time(), 'minutes_10', self::$cron_name );
		}
	}

	/**
	 * Deactivates widget update cron task.
	 *
	 * This is a wrapper over the static method as it provides some syntactic sugar.
	 */
	public function deactivate_cron() {
		self::deactivate_cron_static();
	}

	/**
	 * Deactivates widget update cron task.
	 */
	public static function deactivate_cron_static() {
		$next_scheduled_time = wp_next_scheduled( self::$cron_name );
		wp_unschedule_event( $next_scheduled_time, self::$cron_name );
	}

	/**
	 * Checks if the update cron should be running and returns appropriate result.
	 *
	 * @return bool If the cron should be running or not.
	 */
	public function should_cron_be_running() {
		/**
		 * The cron doesn't need to run empty loops.
		 */
		$widget_instances = $this->get_instances_sites();

		if ( empty( $widget_instances ) || ! is_array( $widget_instances ) ) {
			return false;
		}

		if ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM ) {
			/**
			 * If Jetpack is not active or in offline mode, we don't want to update widget data.
			 */
			if ( ! Jetpack::is_connection_ready() && ! ( new Status() )->is_offline_mode() ) {
				return false;
			}

			/**
			 * If Extra Sidebar Widgets module is not active, we don't need to update widget data.
			 */
			if ( ! Jetpack::is_module_active( 'widgets' ) ) {
				return false;
			}
		}

		/**
		 * If none of the above checks failed, then we definitely want to update widget data.
		 */
		return true;
	}

	/**
	 * Main cron code. Updates all instances of the widget.
	 *
	 * @return bool
	 */
	public function cron_task() {

		/**
		 * If the cron should not be running, disable it.
		 */
		if ( false === $this->should_cron_be_running() ) {
			return true;
		}

		$instances_to_update = $this->get_instances_sites();

		/**
		 * If no instances are found to be updated - stop.
		 */
		if ( empty( $instances_to_update ) || ! is_array( $instances_to_update ) ) {
			return true;
		}

		foreach ( $instances_to_update as $site_url ) {
			$this->update_instance( $site_url );
		}

		return true;
	}

	/**
	 * Get a list of unique sites from all instances of the widget.
	 *
	 * @return array|bool
	 */
	public function get_instances_sites() {

		$widget_settings = $this->wp_get_option( 'widget_jetpack_display_posts_widget' );

		/**
		 * If the widget still hasn't been added anywhere, the config will not be present.
		 *
		 * In such case we don't want to continue execution.
		 */
		if ( false === $widget_settings || ! is_array( $widget_settings ) ) {
			return false;
		}

		$urls = array();

		foreach ( $widget_settings as $widget_instance_data ) {
			if ( isset( $widget_instance_data['url'] ) && ! empty( $widget_instance_data['url'] ) ) {
				$urls[] = $widget_instance_data['url'];
			}
		}

		/**
		 * Make sure only unique URLs are returned.
		 */
		$urls = array_unique( $urls );

		return $urls;
	}

	// MOCKABLES.

	/**
	 * This is just to make method mocks in the unit tests easier.
	 *
	 * @param string $param Option key to get.
	 *
	 * @return mixed
	 *
	 * @codeCoverageIgnore
	 */
	public function wp_get_option( $param ) {
		return get_option( $param );
	}

	/**
	 * This is just to make method mocks in the unit tests easier.
	 *
	 * @param string $option_name  Option name to be added.
	 * @param mixed  $option_value Option value.
	 *
	 * @return mixed
	 *
	 * @codeCoverageIgnore
	 */
	public function wp_add_option( $option_name, $option_value ) {
		return add_option( $option_name, $option_value );
	}

	/**
	 * This is just to make method mocks in the unit tests easier.
	 *
	 * @param string $option_name  Option name to be updated.
	 * @param mixed  $option_value Option value.
	 *
	 * @return mixed
	 *
	 * @codeCoverageIgnore
	 */
	public function wp_update_option( $option_name, $option_value ) {
		return update_option( $option_name, $option_value );
	}
}
