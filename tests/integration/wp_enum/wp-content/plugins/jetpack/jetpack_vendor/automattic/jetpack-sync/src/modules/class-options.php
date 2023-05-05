<?php
/**
 * Options sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

use Automattic\Jetpack\Sync\Defaults;
use Automattic\Jetpack\Sync\Settings;

/**
 * Class to handle sync for options.
 */
class Options extends Module {
	/**
	 * Whitelist for options we want to sync.
	 *
	 * @access private
	 *
	 * @var array
	 */
	private $options_whitelist;

	/**
	 * Contentless options we want to sync.
	 *
	 * @access private
	 *
	 * @var array
	 */
	private $options_contentless;

	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'options';
	}

	/**
	 * Initialize options action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_listeners( $callable ) {
		// Options.
		add_action( 'added_option', $callable, 10, 2 );
		add_action( 'updated_option', $callable, 10, 3 );
		add_action( 'deleted_option', $callable, 10, 1 );

		// Sync Core Icon: Detect changes in Core's Site Icon and make it syncable.
		add_action( 'add_option_site_icon', array( $this, 'jetpack_sync_core_icon' ) );
		add_action( 'update_option_site_icon', array( $this, 'jetpack_sync_core_icon' ) );
		add_action( 'delete_option_site_icon', array( $this, 'jetpack_sync_core_icon' ) );

		// Handle deprecated options.
		add_filter( 'jetpack_options_whitelist', array( $this, 'add_deprecated_options' ) );

		$whitelist_option_handler = array( $this, 'whitelist_options' );
		add_filter( 'jetpack_sync_before_enqueue_deleted_option', $whitelist_option_handler );
		add_filter( 'jetpack_sync_before_enqueue_added_option', $whitelist_option_handler );
		add_filter( 'jetpack_sync_before_enqueue_updated_option', $whitelist_option_handler );
	}

	/**
	 * Initialize options action listeners for full sync.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_full_sync_listeners( $callable ) {
		add_action( 'jetpack_full_sync_options', $callable );
	}

	/**
	 * Initialize the module in the sender.
	 *
	 * @access public
	 */
	public function init_before_send() {
		// Full sync.
		add_filter( 'jetpack_sync_before_send_jetpack_full_sync_options', array( $this, 'expand_options' ) );
	}

	/**
	 * Set module defaults.
	 * Define the options whitelist and contentless options.
	 *
	 * @access public
	 */
	public function set_defaults() {
		$this->update_options_whitelist();
		$this->update_options_contentless();
	}

	/**
	 * Set module defaults at a later time.
	 *
	 * @access public
	 */
	public function set_late_default() {
		/** This filter is already documented in json-endpoints/jetpack/class.wpcom-json-api-get-option-endpoint.php */
		$late_options = apply_filters( 'jetpack_options_whitelist', array() );
		if ( ! empty( $late_options ) && is_array( $late_options ) ) {
			$this->options_whitelist = array_merge( $this->options_whitelist, $late_options );
		}
	}

	/**
	 * Add old deprecated options to the list of options to keep in sync.
	 *
	 * @since 1.14.0
	 *
	 * @access public
	 *
	 * @param array $options The default list of site options.
	 */
	public function add_deprecated_options( $options ) {
		global $wp_version;

		$deprecated_options = array(
			'blacklist_keys'    => '5.5-alpha', // Replaced by disallowed_keys.
			'comment_whitelist' => '5.5-alpha', // Replaced by comment_previously_approved.
		);

		foreach ( $deprecated_options as $option => $version ) {
			if ( version_compare( $wp_version, $version, '<=' ) ) {
				$options[] = $option;
			}
		}

		return $options;
	}

	/**
	 * Enqueue the options actions for full sync.
	 *
	 * @access public
	 *
	 * @param array   $config               Full sync configuration for this sync module.
	 * @param int     $max_items_to_enqueue Maximum number of items to enqueue.
	 * @param boolean $state                True if full sync has finished enqueueing this module, false otherwise.
	 * @return array Number of actions enqueued, and next module state.
	 */
	public function enqueue_full_sync_actions( $config, $max_items_to_enqueue, $state ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		/**
		 * Tells the client to sync all options to the server
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 *
		 * @param boolean Whether to expand options (should always be true)
		 */
		do_action( 'jetpack_full_sync_options', true );

		// The number of actions enqueued, and next module state (true == done).
		return array( 1, true );
	}

	/**
	 * Send the options actions for full sync.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @param int   $send_until The timestamp until the current request can send.
	 * @param array $state This module Full Sync status.
	 *
	 * @return array This module Full Sync status.
	 */
	public function send_full_sync_actions( $config, $send_until, $state ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		// we call this instead of do_action when sending immediately.
		$this->send_action( 'jetpack_full_sync_options', array( true ) );

		// The number of actions enqueued, and next module state (true == done).
		return array( 'finished' => true );
	}

	/**
	 * Retrieve an estimated number of actions that will be enqueued.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return int Number of items yet to be enqueued.
	 */
	public function estimate_full_sync_actions( $config ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return 1;
	}

	/**
	 * Retrieve the actions that will be sent for this module during a full sync.
	 *
	 * @access public
	 *
	 * @return array Full sync actions of this module.
	 */
	public function get_full_sync_actions() {
		return array( 'jetpack_full_sync_options' );
	}

	/**
	 * Retrieve all options as per the current options whitelist.
	 * Public so that we don't have to store so much data all the options twice.
	 *
	 * @access public
	 *
	 * @return array All options.
	 */
	public function get_all_options() {
		$options       = array();
		$random_string = wp_generate_password();
		foreach ( $this->options_whitelist as $option ) {
			if ( 0 === strpos( $option, Settings::SETTINGS_OPTION_PREFIX ) ) {
				$option_value       = Settings::get_setting( str_replace( Settings::SETTINGS_OPTION_PREFIX, '', $option ) );
				$options[ $option ] = $option_value;
			} else {
				$option_value = get_option( $option, $random_string );
				if ( $option_value !== $random_string ) {
					$options[ $option ] = $option_value;
				}
			}
		}

		// Add theme mods.
		$theme_mods_option = 'theme_mods_' . get_option( 'stylesheet' );
		$theme_mods_value  = get_option( $theme_mods_option, $random_string );
		if ( $theme_mods_value === $random_string ) {
			return $options;
		}
		$this->filter_theme_mods( $theme_mods_value );
		$options[ $theme_mods_option ] = $theme_mods_value;
		return $options;
	}

	/**
	 * Update the options whitelist to the default one.
	 *
	 * @access public
	 */
	public function update_options_whitelist() {
		$this->options_whitelist = Defaults::get_options_whitelist();
	}

	/**
	 * Set the options whitelist.
	 *
	 * @access public
	 *
	 * @param array $options The new options whitelist.
	 */
	public function set_options_whitelist( $options ) {
		$this->options_whitelist = $options;
	}

	/**
	 * Get the options whitelist.
	 *
	 * @access public
	 *
	 * @return array The options whitelist.
	 */
	public function get_options_whitelist() {
		return $this->options_whitelist;
	}

	/**
	 * Update the contentless options to the defaults.
	 *
	 * @access public
	 */
	public function update_options_contentless() {
		$this->options_contentless = Defaults::get_options_contentless();
	}

	/**
	 * Get the contentless options.
	 *
	 * @access public
	 *
	 * @return array Array of the contentless options.
	 */
	public function get_options_contentless() {
		return $this->options_contentless;
	}

	/**
	 * Reject any options that aren't whitelisted or contentless.
	 *
	 * @access public
	 *
	 * @param array $args The hook parameters.
	 * @return array $args The hook parameters.
	 */
	public function whitelist_options( $args ) {
		// Reject non-whitelisted options.
		if ( ! $this->is_whitelisted_option( $args[0] ) ) {
			return false;
		}

		// Filter our weird array( false ) value for theme_mods_*.
		if ( 'theme_mods_' === substr( $args[0], 0, 11 ) ) {
			$this->filter_theme_mods( $args[1] );
			if ( isset( $args[2] ) ) {
				$this->filter_theme_mods( $args[2] );
			}
		}

		// Set value(s) of contentless option to empty string(s).
		if ( $this->is_contentless_option( $args[0] ) ) {
			// Create a new array matching length of $args, containing empty strings.
			$empty    = array_fill( 0, count( $args ), '' );
			$empty[0] = $args[0];
			return $empty;
		}

		return $args;
	}

	/**
	 * Whether a certain option is whitelisted for sync.
	 *
	 * @access public
	 *
	 * @param string $option Option name.
	 * @return boolean Whether the option is whitelisted.
	 */
	public function is_whitelisted_option( $option ) {
		return in_array( $option, $this->options_whitelist, true ) || 'theme_mods_' === substr( $option, 0, 11 );
	}

	/**
	 * Whether a certain option is a contentless one.
	 *
	 * @access private
	 *
	 * @param string $option Option name.
	 * @return boolean Whether the option is contentless.
	 */
	private function is_contentless_option( $option ) {
		return in_array( $option, $this->options_contentless, true );
	}

	/**
	 * Filters out falsy values from theme mod options.
	 *
	 * @access private
	 *
	 * @param array $value Option value.
	 */
	private function filter_theme_mods( &$value ) {
		if ( is_array( $value ) && isset( $value[0] ) ) {
			unset( $value[0] );
		}
	}

	/**
	 * Handle changes in the core site icon and sync them.
	 *
	 * @access public
	 */
	public function jetpack_sync_core_icon() {
		$url = get_site_icon_url();

		$jetpack_url = \Jetpack_Options::get_option( 'site_icon_url' );
		if ( defined( 'JETPACK__PLUGIN_DIR' ) ) {
			if ( ! function_exists( 'jetpack_site_icon_url' ) ) {
				require_once JETPACK__PLUGIN_DIR . 'modules/site-icon/site-icon-functions.php';
			}
			$jetpack_url = jetpack_site_icon_url();
		}

		// If there's a core icon, maybe update the option.  If not, fall back to Jetpack's.
		if ( ! empty( $url ) && $jetpack_url !== $url ) {
			// This is the option that is synced with dotcom.
			\Jetpack_Options::update_option( 'site_icon_url', $url );
		} elseif ( empty( $url ) ) {
			\Jetpack_Options::delete_option( 'site_icon_url' );
		}
	}

	/**
	 * Expand all options within a hook before they are serialized and sent to the server.
	 *
	 * @access public
	 *
	 * @param array $args The hook parameters.
	 * @return array $args The hook parameters.
	 */
	public function expand_options( $args ) {
		if ( $args[0] ) {
			return $this->get_all_options();
		}

		return $args;
	}

	/**
	 * Return Total number of objects.
	 *
	 * @param array $config Full Sync config.
	 *
	 * @return int total
	 */
	public function total( $config ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return count( Defaults::get_options_whitelist() );
	}

	/**
	 * Retrieve a set of options by their IDs.
	 *
	 * @access public
	 *
	 * @param string $object_type Object type.
	 * @param array  $ids         Object IDs.
	 * @return array Array of objects.
	 */
	public function get_objects_by_id( $object_type, $ids ) {
		if ( empty( $ids ) || empty( $object_type ) || 'option' !== $object_type ) {
			return array();
		}

		$objects = array();
		foreach ( (array) $ids as $id ) {
			$object = $this->get_object_by_id( $object_type, $id );

			// Only add object if we have the object.
			if ( 'OPTION-DOES-NOT-EXIST' !== $object ) {
				if ( 'all' === $id ) {
					// If all was requested it contains all options and can simply be returned.
					return $object;
				}
				$objects[ $id ] = $object;
			}
		}

		return $objects;
	}

	/**
	 * Retrieve an option by its name.
	 *
	 * @access public
	 *
	 * @param string $object_type Type of the sync object.
	 * @param string $id          ID of the sync object.
	 * @return mixed              Value of Option or 'OPTION-DOES-NOT-EXIST' if not found.
	 */
	public function get_object_by_id( $object_type, $id ) {
		if ( 'option' === $object_type ) {
			// Utilize Random string as default value to distinguish between false and not exist.
			$random_string = wp_generate_password();
			// Only whitelisted options can be returned.
			if ( in_array( $id, $this->options_whitelist, true ) ) {
				if ( 0 === strpos( $id, Settings::SETTINGS_OPTION_PREFIX ) ) {
					$option_value = Settings::get_setting( str_replace( Settings::SETTINGS_OPTION_PREFIX, '', $id ) );
					return $option_value;
				} else {
					$option_value = get_option( $id, $random_string );
					if ( $option_value !== $random_string ) {
						return $option_value;
					}
				}
			} elseif ( 'all' === $id ) {
				return $this->get_all_options();
			}
		}

		return 'OPTION-DOES-NOT-EXIST';
	}

}
