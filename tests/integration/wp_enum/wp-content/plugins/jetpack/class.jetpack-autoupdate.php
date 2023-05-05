<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Handles items that have been selected for automatic updates.
 * Hooks into WP_Automatic_Updater
 *
 * @package automattic/jetpack
 */

/**
 * Handles items that have been selected for automatic updates.
 * Hooks into WP_Automatic_Updater
 */
class Jetpack_Autoupdate {

	/**
	 * Results.
	 *
	 * @var array
	 */
	private $results = array();

	/**
	 * Expected updates.
	 *
	 * @var array
	 */
	private $expected = array();

	/**
	 * Successful updates.
	 *
	 * @var array
	 */
	private $success = array(
		'plugin' => array(),
		'theme'  => array(),
	);

	/**
	 * Failed updates.
	 *
	 * @var array
	 */
	private $failed = array(
		'plugin' => array(),
		'theme'  => array(),
	);

	/**
	 * Static instance.
	 *
	 * @var self
	 */
	private static $instance = null;

	/**
	 * Initialize and fetch the static instance.
	 *
	 * @return self
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new Jetpack_Autoupdate();
		}

		return self::$instance;
	}

	/** Constructor. */
	private function __construct() {
		if (
			/** This filter is documented in class.jetpack-json-api-endpoint.php */
			apply_filters( 'jetpack_json_manage_api_enabled', true )
		) {
			add_filter( 'auto_update_theme', array( $this, 'autoupdate_theme' ), 10, 2 );
			add_filter( 'auto_update_core', array( $this, 'autoupdate_core' ), 10, 2 );
			add_filter( 'auto_update_translation', array( $this, 'autoupdate_translation' ), 10, 2 );
			add_action( 'automatic_updates_complete', array( $this, 'automatic_updates_complete' ), 999, 1 );
		}
	}

	/**
	 * Filter function for `auto_update_translation`.
	 *
	 * @param bool|null $update Whether to update.
	 * @param object    $item  The update offer.
	 * @return bool|null Whether to update.
	 */
	public function autoupdate_translation( $update, $item ) {
		// Autoupdate all translations.
		if ( Jetpack_Options::get_option( 'autoupdate_translations', false ) ) {
			return true;
		}

		// Themes.
		$autoupdate_themes_translations = Jetpack_Options::get_option( 'autoupdate_themes_translations', array() );
		$autoupdate_theme_list          = Jetpack_Options::get_option( 'autoupdate_themes', array() );

		if ( ( in_array( $item->slug, $autoupdate_themes_translations, true ) || in_array( $item->slug, $autoupdate_theme_list, true ) )
			&& 'theme' === $item->type
		) {
			$this->expect( $item->type . ':' . $item->slug, 'translation' );

			return true;
		}

		// Plugins.
		$autoupdate_plugin_translations = Jetpack_Options::get_option( 'autoupdate_plugins_translations', array() );
		$autoupdate_plugin_list         = (array) get_site_option( 'auto_update_plugins', array() );
		$plugin_files                   = array_unique( array_merge( $autoupdate_plugin_list, $autoupdate_plugin_translations ) );
		$plugin_slugs                   = array_map( array( __CLASS__, 'get_plugin_slug' ), $plugin_files );

		if ( in_array( $item->slug, $plugin_slugs, true )
			&& 'plugin' === $item->type
		) {
			$this->expect( $item->type . ':' . $item->slug, 'translation' );
			return true;
		}

		return $update;
	}

	/**
	 * Filter function for `auto_update_theme`.
	 *
	 * @param bool|null $update Whether to update.
	 * @param object    $item  The update offer.
	 * @return bool|null Whether to update.
	 */
	public function autoupdate_theme( $update, $item ) {
		$autoupdate_theme_list = Jetpack_Options::get_option( 'autoupdate_themes', array() );
		if ( in_array( $item->theme, $autoupdate_theme_list, true ) ) {
			$this->expect( $item->theme, 'theme' );
			return true;
		}

		return $update;
	}

	/**
	 * Filter function for `auto_update_core`.
	 *
	 * @param bool|null $update Whether to update.
	 * @return bool|null Whether to update.
	 */
	public function autoupdate_core( $update ) {
		$autoupdate_core = Jetpack_Options::get_option( 'autoupdate_core', false );
		if ( $autoupdate_core ) {
			return $autoupdate_core;
		}

		return $update;
	}

	/**
	 * Stores the an item identifier to the expected array.
	 *
	 * @param string $item Example: 'jetpack/jetpack.php' for type 'plugin' or 'twentyfifteen' for type 'theme'.
	 * @param string $type 'plugin' or 'theme'.
	 */
	private function expect( $item, $type ) {
		if ( ! isset( $this->expected[ $type ] ) ) {
			$this->expected[ $type ] = array();
		}
		$this->expected[ $type ][] = $item;
	}

	/**
	 * On completion of an automatic update, let's store the results.
	 *
	 * @param mixed $results - Sent by WP_Automatic_Updater after it completes an autoupdate action. Results may be empty.
	 */
	public function automatic_updates_complete( $results ) {
		if ( empty( $this->expected ) ) {
			return;
		}
		$this->results = empty( $results ) ? self::get_possible_failures() : $results;

		add_action( 'shutdown', array( $this, 'bump_stats' ) );

		Jetpack::init();

		$items_to_log = array( 'plugin', 'theme', 'translation' );
		foreach ( $items_to_log as $items ) {
			$this->log_items( $items );
		}

		Jetpack::log( 'autoupdates', $this->get_log() );
	}

	/**
	 * Get log data.
	 *
	 * @return array Data.
	 */
	public function get_log() {
		return array(
			'results' => $this->results,
			'failed'  => $this->failed,
			'success' => $this->success,
		);
	}

	/**
	 * Iterates through expected items ( plugins or themes ) and compares them to actual results.
	 *
	 * @param string $items 'plugin' or 'theme'.
	 */
	private function log_items( $items ) {
		if ( ! isset( $this->expected[ $items ] ) ) {
			return;
		}

		$item_results = $this->get_successful_updates( $items );

		if ( is_array( $this->expected[ $items ] ) ) {
			foreach ( $this->expected[ $items ] as $item ) {
				if ( in_array( $item, $item_results, true ) ) {
					$this->success[ $items ][] = $item;
				} else {
					$this->failed[ $items ][] = $item;
				}
			}
		}
	}

	/**
	 * Bump stats.
	 */
	public function bump_stats() {
		$instance = Jetpack::init();
		$log      = array();
		// Bump numbers.

		if ( ! empty( $this->success['theme'] ) ) {
			$instance->stat( 'autoupdates/theme-success', count( $this->success['theme'] ) );
			$log['themes_success'] = $this->success['theme'];
		}

		if ( ! empty( $this->failed['theme'] ) ) {
			$instance->stat( 'autoupdates/theme-fail', count( $this->failed['theme'] ) );
			$log['themes_failed'] = $this->failed['theme'];
		}

		$instance->do_stats( 'server_side' );

		// Send a more detailed log to logstash.
		if ( ! empty( $log ) ) {
			$xml            = new Jetpack_IXR_Client(
				array(
					'user_id' => get_current_user_id(),
				)
			);
			$log['blog_id'] = Jetpack_Options::get_option( 'id' );
			$xml->query( 'jetpack.debug_autoupdate', $log );
		}
	}

	/**
	 * Parses the autoupdate results generated by WP_Automatic_Updater and returns a simple array of successful items.
	 *
	 * @param string $type 'plugin' or 'theme'.
	 * @return array
	 */
	private function get_successful_updates( $type ) {
		$successful_updates = array();

		if ( ! isset( $this->results[ $type ] ) ) {
			return $successful_updates;
		}

		foreach ( $this->results[ $type ] as $result ) {
			if ( $result->result ) {
				switch ( $type ) {
					case 'theme':
						$successful_updates[] = $result->item->theme;
						break;
					case 'translation':
						$successful_updates[] = $result->item->type . ':' . $result->item->slug;
						break;
				}
			}
		}

		return $successful_updates;
	}

	/**
	 * Get possible failure codes.
	 *
	 * @return string[] Failure codes.
	 */
	public static function get_possible_failures() {
		$result = array();
		// Lets check some reasons why it might not be working as expected.
		include_once ABSPATH . '/wp-admin/includes/admin.php';
		include_once ABSPATH . '/wp-admin/includes/class-wp-upgrader.php';
		$upgrader = new WP_Automatic_Updater();

		if ( $upgrader->is_disabled() ) {
			$result[] = 'autoupdates-disabled';
		}
		if ( ! is_main_site() ) {
			$result[] = 'is-not-main-site';
		}
		if ( ! is_main_network() ) {
			$result[] = 'is-not-main-network';
		}
		if ( $upgrader->is_vcs_checkout( ABSPATH ) ) {
			$result[] = 'site-on-vcs';
		}
		if ( $upgrader->is_vcs_checkout( WP_PLUGIN_DIR ) ) {
			$result[] = 'plugin-directory-on-vcs';
		}
		if ( $upgrader->is_vcs_checkout( WP_CONTENT_DIR ) ) {
			$result[] = 'content-directory-on-vcs';
		}
		$lock = get_option( 'auto_updater.lock' );
		if ( $lock > ( time() - HOUR_IN_SECONDS ) ) {
			$result[] = 'lock-is-set';
		}
		$skin = new Automatic_Upgrader_Skin();
		include_once ABSPATH . 'wp-admin/includes/file.php';
		include_once ABSPATH . 'wp-admin/includes/template.php';
		if ( ! $skin->request_filesystem_credentials( false, ABSPATH, false ) ) {
			$result[] = 'no-system-write-access';
		}
		if ( ! $skin->request_filesystem_credentials( false, WP_PLUGIN_DIR, false ) ) {
			$result[] = 'no-plugin-directory-write-access';
		}
		if ( ! $skin->request_filesystem_credentials( false, WP_CONTENT_DIR, false ) ) {
			$result[] = 'no-wp-content-directory-write-access';
		}

		return $result;
	}

	/**
	 * Get the plugin slug.
	 *
	 * @param string $plugin_file Plugin file.
	 * @return string Slug.
	 */
	public static function get_plugin_slug( $plugin_file ) {
		$update_plugins = get_site_transient( 'update_plugins' );
		if ( isset( $update_plugins->no_update ) ) {
			if ( isset( $update_plugins->no_update[ $plugin_file ]->slug ) ) {
				$slug = $update_plugins->no_update[ $plugin_file ]->slug;
			}
		}
		if ( empty( $slug ) && isset( $update_plugins->response ) ) {
			if ( isset( $update_plugins->response[ $plugin_file ]->slug ) ) {
				$slug = $update_plugins->response[ $plugin_file ]->slug;
			}
		}

		// Try to infer from the plugin file if not cached.
		if ( empty( $slug ) ) {
			$slug = dirname( $plugin_file );
			if ( '.' === $slug ) {
				$slug = preg_replace( '/(.+)\.php$/', '$1', $plugin_file );
			}
		}
		return $slug;
	}

}

Jetpack_Autoupdate::init();
