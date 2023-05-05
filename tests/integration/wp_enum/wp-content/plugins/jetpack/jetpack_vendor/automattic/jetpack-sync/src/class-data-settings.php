<?php
/**
 * The Data Settings class.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

/**
 * The Data_Settings class
 */
class Data_Settings {

	/**
	 * The data that must be synced for every synced site.
	 */
	const MUST_SYNC_DATA_SETTINGS = array(
		'jetpack_sync_modules'             => array(
			'Automattic\\Jetpack\\Sync\\Modules\\Callables',
			'Automattic\\Jetpack\\Sync\\Modules\\Constants',
			'Automattic\\Jetpack\\Sync\\Modules\\Full_Sync_Immediately', // enable Initial Sync on Site Connection.
			'Automattic\\Jetpack\\Sync\\Modules\\Options',
			'Automattic\\Jetpack\\Sync\\Modules\\Updates',
		),
		'jetpack_sync_callable_whitelist'  => array(
			'site_url'                => array( 'Automattic\\Jetpack\\Connection\\Urls', 'site_url' ),
			'home_url'                => array( 'Automattic\\Jetpack\\Connection\\Urls', 'home_url' ),
			'get_plugins'             => array( 'Automattic\\Jetpack\\Sync\\Functions', 'get_plugins' ),
			'get_themes'              => array( 'Automattic\\Jetpack\\Sync\\Functions', 'get_themes' ),
			'paused_plugins'          => array( 'Automattic\\Jetpack\\Sync\\Functions', 'get_paused_plugins' ),
			'paused_themes'           => array( 'Automattic\\Jetpack\\Sync\\Functions', 'get_paused_themes' ),
			'timezone'                => array( 'Automattic\\Jetpack\\Sync\\Functions', 'get_timezone' ),
			'wp_get_environment_type' => 'wp_get_environment_type',
			'wp_max_upload_size'      => 'wp_max_upload_size',
			'wp_version'              => array( 'Automattic\\Jetpack\\Sync\\Functions', 'wp_version' ),
		),
		'jetpack_sync_constants_whitelist' => array(
			'ABSPATH',
			'ALTERNATE_WP_CRON',
			'ATOMIC_CLIENT_ID',
			'AUTOMATIC_UPDATER_DISABLED',
			'DISABLE_WP_CRON',
			'DISALLOW_FILE_EDIT',
			'DISALLOW_FILE_MODS',
			'EMPTY_TRASH_DAYS',
			'FS_METHOD',
			'IS_PRESSABLE',
			'PHP_VERSION',
			'WP_ACCESSIBLE_HOSTS',
			'WP_AUTO_UPDATE_CORE',
			'WP_CONTENT_DIR',
			'WP_CRON_LOCK_TIMEOUT',
			'WP_DEBUG',
			'WP_HTTP_BLOCK_EXTERNAL',
			'WP_MAX_MEMORY_LIMIT',
			'WP_MEMORY_LIMIT',
			'WP_POST_REVISIONS',
		),
		'jetpack_sync_options_whitelist'   => array(
			/**
			 * Sync related options
			 */
			'jetpack_sync_non_blocking',
			'jetpack_sync_non_public_post_stati',
			'jetpack_sync_settings_comment_meta_whitelist',
			'jetpack_sync_settings_post_meta_whitelist',
			'jetpack_sync_settings_post_types_blacklist',
			'jetpack_sync_settings_taxonomies_blacklist',
			'jetpack_sync_settings_dedicated_sync_enabled',
			/**
			 * Connection related options
			 */
			'jetpack_connection_active_plugins',
			/**
			 * Generic site options
			 */
			'blog_charset',
			'blog_public',
			'blogdescription',
			'blogname',
			'permalink_structure',
			'stylesheet',
			'time_format',
			'timezone_string',
		),
	);

	const MODULE_FILTER_MAPPING = array(
		'Automattic\\Jetpack\\Sync\\Modules\\Options'   => array(
			'jetpack_sync_options_whitelist',
			'jetpack_sync_options_contentless',
		),
		'Automattic\\Jetpack\\Sync\\Modules\\Constants' => array(
			'jetpack_sync_constants_whitelist',
		),
		'Automattic\\Jetpack\\Sync\\Modules\\Callables' => array(
			'jetpack_sync_callable_whitelist',
			'jetpack_sync_multisite_callable_whitelist',
		),
		'Automattic\\Jetpack\\Sync\\Modules\\Posts'     => array(
			'jetpack_sync_post_meta_whitelist',
		),
		'Automattic\\Jetpack\\Sync\\Modules\\Comments'  => array(
			'jetpack_sync_comment_meta_whitelist',
		),
		'Automattic\\Jetpack\\Sync\\Modules\\Users'     => array(
			'jetpack_sync_capabilities_whitelist',
		),
		'Automattic\\Jetpack\\Sync\\Modules\\Import'    => array(
			'jetpack_sync_known_importers',
		),
	);

	const MODULES_FILTER_NAME = 'jetpack_sync_modules';

	/**
	 * The static data settings array which contains the aggregated data settings for
	 * each sync filter.
	 *
	 * @var array
	 */
	private static $data_settings = array();

	/**
	 * The static array which contains the list of filter hooks that have already been set up.
	 *
	 * @var array
	 */
	private static $set_filter_hooks = array();

	/**
	 * Adds the data settings provided by a plugin to the Sync data settings.
	 *
	 * @param array $plugin_settings The array provided by the plugin. The array must use filters
	 *                               from the DATA_FILTER_DEFAULTS list as keys.
	 */
	public function add_settings_list( $plugin_settings = array() ) {
		if ( empty( $plugin_settings ) || ! is_array( $plugin_settings ) ) {
			/*
			 * No custom plugin settings, so use defaults for everything and bail early.
			 */
			$this->set_all_defaults();
			return;
		}

		$this->add_filters_custom_settings_and_hooks( $plugin_settings );

		if ( ! did_action( 'jetpack_sync_add_required_data_settings' ) ) {
			$this->add_required_settings();
			/**
			 * Fires when the required settings have been adding to the static
			 * data_settings array.
			 *
			 * @since 1.29.2
			 *
			 * @module sync
			 */
			do_action( 'jetpack_sync_add_required_data_settings' );
		}
	}

	/**
	 * Sets the default values for sync modules and all sync data filters.
	 */
	private function set_all_defaults() {
		$this->add_sync_filter_setting( self::MODULES_FILTER_NAME, Modules::DEFAULT_SYNC_MODULES );

		foreach ( array_keys( Default_Filter_Settings::DATA_FILTER_DEFAULTS ) as $filter ) {
			$this->add_sync_filter_setting( $filter, $this->get_default_setting_for_filter( $filter ) );
		}
	}

	/**
	 * Returns the default settings for the given filter.
	 *
	 * @param string $filter The filter name.
	 *
	 * @return array The filter's default settings array.
	 */
	private function get_default_setting_for_filter( $filter ) {
		if ( self::MODULES_FILTER_NAME === $filter ) {
			return Modules::DEFAULT_SYNC_MODULES;
		}

		return ( new Default_Filter_Settings() )->get_default_settings( $filter );
	}

	/**
	 * Adds the custom settings and sets up the necessary filter hooks.
	 *
	 * @param array $filters_settings The custom settings.
	 */
	private function add_filters_custom_settings_and_hooks( $filters_settings ) {
		if ( isset( $filters_settings[ self::MODULES_FILTER_NAME ] ) && is_array( $filters_settings[ self::MODULES_FILTER_NAME ] ) ) {
			$this->add_custom_filter_setting( self::MODULES_FILTER_NAME, $filters_settings[ self::MODULES_FILTER_NAME ] );
			$enabled_modules = $filters_settings[ self::MODULES_FILTER_NAME ];
		} else {
			$this->add_sync_filter_setting( self::MODULES_FILTER_NAME, Modules::DEFAULT_SYNC_MODULES );
			$enabled_modules = Modules::DEFAULT_SYNC_MODULES;
		}

		$all_modules = Modules::DEFAULT_SYNC_MODULES;

		foreach ( $all_modules as $module ) {
			if ( in_array( $module, $enabled_modules, true ) || in_array( $module, self::MUST_SYNC_DATA_SETTINGS['jetpack_sync_modules'], true ) ) {
				$this->add_filters_for_enabled_module( $module, $filters_settings );
			} else {
				$this->add_filters_for_disabled_module( $module );
			}
		}
	}

	/**
	 * Adds the filters for the provided enabled module. If the settings provided custom filter settings
	 * for the module's filters, those are used. Otherwise, the filter's default settings are used.
	 *
	 * @param string $module The module name.
	 * @param array  $filters_settings The settings for the filters.
	 */
	private function add_filters_for_enabled_module( $module, $filters_settings ) {
		$module_mapping     = self::MODULE_FILTER_MAPPING;
		$filters_for_module = isset( $module_mapping[ $module ] ) ? $module_mapping[ $module ] : array();

		foreach ( $filters_for_module as $filter ) {
			if ( isset( $filters_settings[ $filter ] ) ) {
				$this->add_custom_filter_setting( $filter, $filters_settings[ $filter ] );
			} else {
				$this->add_sync_filter_setting( $filter, $this->get_default_setting_for_filter( $filter ) );
			}
		}
	}

	/**
	 * Adds the filters for the provided disabled module. The disabled module's associated filter settings are
	 * set to an empty array.
	 *
	 * @param string $module The module name.
	 */
	private function add_filters_for_disabled_module( $module ) {
		$module_mapping     = self::MODULE_FILTER_MAPPING;
		$filters_for_module = isset( $module_mapping[ $module ] ) ? $module_mapping[ $module ] : array();

		foreach ( $filters_for_module as $filter ) {
			$this->add_custom_filter_setting( $filter, array() );
		}
	}

	/**
	 * Adds the provided custom setting for a filter. If the filter setting isn't valid, the default
	 * value is used.
	 *
	 * If the filter's hook hasn't already been set up, it gets set up.
	 *
	 * @param string $filter The filter.
	 * @param array  $setting The filter setting.
	 */
	private function add_custom_filter_setting( $filter, $setting ) {
		if ( ! $this->is_valid_filter_setting( $filter, $setting ) ) {
			/*
			 * The provided setting isn't valid, so use the default for this filter.
			 * We're using the default values so there's no need to set the filter hook.
			 */
			$this->add_sync_filter_setting( $filter, $this->get_default_setting_for_filter( $filter ) );
			return;
		}

		if ( ! isset( static::$set_filter_hooks[ $filter ] ) ) {
			// First time a custom modules setting is provided, so set the filter hook.
			add_filter( $filter, array( $this, 'sync_data_filter_hook' ) );
			static::$set_filter_hooks[ $filter ] = 1;
		}

		$this->add_sync_filter_setting( $filter, $setting );
	}

	/**
	 * Determines whether the filter setting is valid. The setting array is in the correct format (associative or indexed).
	 *
	 * @param string $filter The filter to check.
	 * @param array  $filter_settings The filter settings.
	 *
	 * @return bool Whether the filter settings can be used.
	 */
	private function is_valid_filter_setting( $filter, $filter_settings ) {
		if ( ! is_array( $filter_settings ) ) {
			// The settings for each filter must be an array.
			return false;
		}

		if ( empty( $filter_settings ) ) {
			// Empty settings are allowed.
			return true;
		}

		$indexed_array = isset( $filter_settings[0] );
		if ( in_array( $filter, Default_Filter_Settings::ASSOCIATIVE_FILTERS, true ) && ! $indexed_array ) {
				return true;
		} elseif ( ! in_array( $filter, Default_Filter_Settings::ASSOCIATIVE_FILTERS, true ) && $indexed_array ) {
			return true;
		}

		return false;
	}

	/**
	 * Adds the data settings that are always required for every plugin that uses Sync.
	 */
	private function add_required_settings() {
		foreach ( self::MUST_SYNC_DATA_SETTINGS as $filter => $setting ) {
			// If the corresponding setting is already set and matches the default one, no need to proceed.
			if ( isset( static::$data_settings[ $filter ] ) && static::$data_settings[ $filter ] === $this->get_default_setting_for_filter( $filter ) ) {
				continue;
			}
			$this->add_custom_filter_setting( $filter, $setting );
		}
	}

	/**
	 * Adds the provided data setting for the provided filter.
	 *
	 * @param string $filter The filter name.
	 * @param array  $value The data setting.
	 */
	private function add_sync_filter_setting( $filter, $value ) {
		if ( ! isset( static::$data_settings[ $filter ] ) ) {
			static::$data_settings[ $filter ] = $value;
			return;
		}

		if ( in_array( $filter, Default_Filter_Settings::ASSOCIATIVE_FILTERS, true ) ) {
			$this->add_associative_filter_setting( $filter, $value );
		} else {
			$this->add_indexed_filter_setting( $filter, $value );
		}
	}

	/**
	 * Adds the provided data setting for the provided filter. This method handles
	 * adding settings to data that is stored as an associative array.
	 *
	 * @param string $filter  The filter name.
	 * @param array  $settings The data settings.
	 */
	private function add_associative_filter_setting( $filter, $settings ) {
		foreach ( $settings as $key => $item ) {
			if ( ! array_key_exists( $key, static::$data_settings[ $filter ] ) ) {
				static::$data_settings[ $filter ][ $key ] = $item;
			}
		}
	}

	/**
	 * Adds the provided data setting for the provided filter. This method handles
	 * adding settings to data that is stored as an indexed array.
	 *
	 * @param string $filter  The filter name.
	 * @param array  $settings The data settings.
	 */
	private function add_indexed_filter_setting( $filter, $settings ) {
		static::$data_settings[ $filter ] = array_unique(
			array_merge(
				static::$data_settings[ $filter ],
				$settings
			)
		);
	}

	/**
	 * The callback function added to the sync data filters. Combines the list in the $data_settings property
	 * with any non-default values from the received array.
	 *
	 * @param array $filtered_values The data revieved from the filter.
	 *
	 * @return array The data settings for the filter.
	 */
	public function sync_data_filter_hook( $filtered_values ) {
		if ( ! is_array( $filtered_values ) ) {
			// Something is wrong with the input, so set it to an empty array.
			$filtered_values = array();
		}

		$current_filter = current_filter();

		if ( ! isset( static::$data_settings[ $current_filter ] ) ) {
			return $filtered_values;
		}

		if ( in_array( $current_filter, Default_Filter_Settings::ASSOCIATIVE_FILTERS, true ) ) {
			$extra_filters = array_diff_key( $filtered_values, $this->get_default_setting_for_filter( $current_filter ) );
			$this->add_associative_filter_setting( $current_filter, $extra_filters );
			return static::$data_settings[ $current_filter ];
		}

		$extra_filters = array_diff( $filtered_values, $this->get_default_setting_for_filter( $current_filter ) );
		$this->add_indexed_filter_setting( $current_filter, $extra_filters );
		return static::$data_settings[ $current_filter ];
	}

	/**
	 * Sets the $data_settings property to an empty array. This is useful for testing.
	 */
	public function empty_data_settings_and_hooks() {
		static::$data_settings    = array();
		static::$set_filter_hooks = array();
	}

	/**
	 * Returns the $data_settings property.
	 *
	 * @return array The data_settings property.
	 */
	public function get_data_settings() {
		return static::$data_settings;
	}
}
