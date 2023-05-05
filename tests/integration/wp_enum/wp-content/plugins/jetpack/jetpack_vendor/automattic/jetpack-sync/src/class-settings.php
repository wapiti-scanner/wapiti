<?php
/**
 * Sync settings.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

/**
 * Class to manage the sync settings.
 */
class Settings {
	/**
	 * Prefix, used for the sync settings option names.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const SETTINGS_OPTION_PREFIX = 'jetpack_sync_settings_';

	/**
	 * A whitelist of valid settings.
	 *
	 * @access public
	 * @static
	 *
	 * @var array
	 */
	public static $valid_settings = array(
		'dequeue_max_bytes'                      => true,
		'upload_max_bytes'                       => true,
		'upload_max_rows'                        => true,
		'sync_wait_time'                         => true,
		'sync_wait_threshold'                    => true,
		'enqueue_wait_time'                      => true,
		'max_queue_size'                         => true,
		'max_queue_lag'                          => true,
		'queue_max_writes_sec'                   => true,
		'post_types_blacklist'                   => true,
		'taxonomies_blacklist'                   => true,
		'disable'                                => true,
		'network_disable'                        => true,
		'render_filtered_content'                => true,
		'post_meta_whitelist'                    => true,
		'comment_meta_whitelist'                 => true,
		'max_enqueue_full_sync'                  => true,
		'max_queue_size_full_sync'               => true,
		'sync_via_cron'                          => true,
		'cron_sync_time_limit'                   => true,
		'known_importers'                        => true,
		'term_relationships_full_sync_item_size' => true,
		'sync_sender_enabled'                    => true,
		'full_sync_sender_enabled'               => true,
		'full_sync_send_duration'                => true,
		'full_sync_limits'                       => true,
		'checksum_disable'                       => true,
		'dedicated_sync_enabled'                 => true,
	);

	/**
	 * Whether WordPress is currently running an import.
	 *
	 * @access public
	 * @static
	 *
	 * @var null|boolean
	 */
	public static $is_importing;

	/**
	 * Whether WordPress is currently running a WP cron request.
	 *
	 * @access public
	 * @static
	 *
	 * @var null|boolean
	 */
	public static $is_doing_cron;

	/**
	 * Whether we're currently syncing.
	 *
	 * @access public
	 * @static
	 *
	 * @var null|boolean
	 */
	public static $is_syncing;

	/**
	 * Whether we're currently sending sync items.
	 *
	 * @access public
	 * @static
	 *
	 * @var null|boolean
	 */
	public static $is_sending;

	/**
	 * Retrieve all settings with their current values.
	 *
	 * @access public
	 * @static
	 *
	 * @return array All current settings.
	 */
	public static function get_settings() {
		$settings = array();
		foreach ( array_keys( self::$valid_settings ) as $setting ) {
			$settings[ $setting ] = self::get_setting( $setting );
		}

		return $settings;
	}

	/**
	 * Fetches the setting. It saves it if the setting doesn't exist, so that it gets
	 * autoloaded on page load rather than re-queried every time.
	 *
	 * @access public
	 * @static
	 *
	 * @param string $setting The setting name.
	 * @return mixed The setting value.
	 */
	public static function get_setting( $setting ) {
		if ( ! isset( self::$valid_settings[ $setting ] ) ) {
			return false;
		}

		if ( self::is_network_setting( $setting ) ) {
			if ( is_multisite() ) {
				$value = get_site_option( self::SETTINGS_OPTION_PREFIX . $setting );
			} else {
				// On single sites just return the default setting.
				return Defaults::get_default_setting( $setting );
			}
		} else {
			$value = get_option( self::SETTINGS_OPTION_PREFIX . $setting );
		}

		if ( false === $value ) { // No default value is set.
			$value = Defaults::get_default_setting( $setting );
			if ( self::is_network_setting( $setting ) ) {
				update_site_option( self::SETTINGS_OPTION_PREFIX . $setting, $value );
			} else {
				// We set one so that it gets autoloaded.
				update_option( self::SETTINGS_OPTION_PREFIX . $setting, $value, true );
			}
		}

		if ( is_numeric( $value ) ) {
			$value = (int) $value;
		}
		$default_array_value = null;
		switch ( $setting ) {
			case 'post_types_blacklist':
				$default_array_value = Defaults::$blacklisted_post_types;
				break;
			case 'taxonomies_blacklist':
				$default_array_value = Defaults::$blacklisted_taxonomies;
				break;
			case 'post_meta_whitelist':
				$default_array_value = Defaults::get_post_meta_whitelist();
				break;
			case 'comment_meta_whitelist':
				$default_array_value = Defaults::get_comment_meta_whitelist();
				break;
			case 'known_importers':
				$default_array_value = Defaults::get_known_importers();
				break;
		}

		if ( $default_array_value ) {
			if ( is_array( $value ) ) {
				$value = array_unique( array_merge( $value, $default_array_value ) );
			} else {
				$value = $default_array_value;
			}
		}

		return $value;
	}

	/**
	 * Change multiple settings in the same time.
	 *
	 * @access public
	 * @static
	 *
	 * @param array $new_settings The new settings.
	 */
	public static function update_settings( $new_settings ) {
		$validated_settings = array_intersect_key( $new_settings, self::$valid_settings );
		foreach ( $validated_settings as $setting => $value ) {

			if ( self::is_network_setting( $setting ) ) {
				if ( is_multisite() && is_main_site() ) {
					$updated = update_site_option( self::SETTINGS_OPTION_PREFIX . $setting, $value );
				}
			} else {
				$updated = update_option( self::SETTINGS_OPTION_PREFIX . $setting, $value, true );
			}

			// If we set the disabled option to true, clear the queues.
			if ( ( 'disable' === $setting || 'network_disable' === $setting ) && (bool) $value ) {
				$listener = Listener::get_instance();
				$listener->get_sync_queue()->reset();
				$listener->get_full_sync_queue()->reset();
			}

			// Do not enable Dedicated Sync if we cannot spawn a Dedicated Sync request.
			if ( 'dedicated_sync_enabled' === $setting && $updated && (bool) $value ) {
				if ( ! Dedicated_Sender::can_spawn_dedicated_sync_request() ) {
					update_option( self::SETTINGS_OPTION_PREFIX . $setting, 0, true );
				}
			}
		}
	}

	/**
	 * Whether the specified setting is a network setting.
	 *
	 * @access public
	 * @static
	 *
	 * @param string $setting Setting name.
	 * @return boolean Whether the setting is a network setting.
	 */
	public static function is_network_setting( $setting ) {
		return strpos( $setting, 'network_' ) === 0;
	}

	/**
	 * Returns escaped SQL for blacklisted post types.
	 * Can be injected directly into a WHERE clause.
	 *
	 * @access public
	 * @static
	 *
	 * @return string SQL WHERE clause.
	 */
	public static function get_blacklisted_post_types_sql() {
		return 'post_type NOT IN (\'' . join( '\', \'', array_map( 'esc_sql', self::get_setting( 'post_types_blacklist' ) ) ) . '\')';
	}

	/**
	 * Returns escaped values for disallowed post types.
	 *
	 * @access public
	 * @static
	 *
	 * @return array Post type filter values
	 */
	public static function get_disallowed_post_types_structured() {
		return array(
			'post_type' => array(
				'operator' => 'NOT IN',
				'values'   => array_map( 'esc_sql', self::get_setting( 'post_types_blacklist' ) ),
			),
		);
	}

	/**
	 * Returns escaped SQL for blacklisted taxonomies.
	 * Can be injected directly into a WHERE clause.
	 *
	 * @access public
	 * @static
	 *
	 * @return string SQL WHERE clause.
	 */
	public static function get_blacklisted_taxonomies_sql() {
		return "taxonomy NOT IN ('" . join( "', '", array_map( 'esc_sql', self::get_setting( 'taxonomies_blacklist' ) ) ) . "')";
	}

	/**
	 * Returns escaped SQL for blacklisted post meta.
	 * Can be injected directly into a WHERE clause.
	 *
	 * @access public
	 * @static
	 *
	 * @return string SQL WHERE clause.
	 */
	public static function get_whitelisted_post_meta_sql() {
		return 'meta_key IN (\'' . join( '\', \'', array_map( 'esc_sql', self::get_setting( 'post_meta_whitelist' ) ) ) . '\')';
	}

	/**
	 * Returns escaped SQL for allowed post meta keys.
	 *
	 * @access public
	 * @static
	 *
	 * @return array Meta keys filter values
	 */
	public static function get_allowed_post_meta_structured() {
		return array(
			'meta_key' => array(
				'operator' => 'IN',
				'values'   => array_map( 'esc_sql', self::get_setting( 'post_meta_whitelist' ) ),
			),
		);
	}

	/**
	 * Returns structured SQL clause for blacklisted taxonomies.
	 *
	 * @access public
	 * @static
	 *
	 * @return array taxonomies filter values
	 */
	public static function get_blacklisted_taxonomies_structured() {
		return array(
			'taxonomy' => array(
				'operator' => 'NOT IN',
				'values'   => array_map( 'esc_sql', self::get_setting( 'taxonomies_blacklist' ) ),
			),
		);
	}

	/**
	 * Returns structured SQL clause for allowed taxonomies.
	 *
	 * @access public
	 * @static
	 *
	 * @return array taxonomies filter values
	 */
	public static function get_allowed_taxonomies_structured() {
		global $wp_taxonomies;

		$allowed_taxonomies = array_keys( $wp_taxonomies );
		$allowed_taxonomies = array_diff( $allowed_taxonomies, self::get_setting( 'taxonomies_blacklist' ) );
		return array(
			'taxonomy' => array(
				'operator' => 'IN',
				'values'   => array_map( 'esc_sql', $allowed_taxonomies ),
			),
		);
	}

	/**
	 * Returns escaped SQL for blacklisted comment meta.
	 * Can be injected directly into a WHERE clause.
	 *
	 * @access public
	 * @static
	 *
	 * @return string SQL WHERE clause.
	 */
	public static function get_whitelisted_comment_meta_sql() {
		return 'meta_key IN (\'' . join( '\', \'', array_map( 'esc_sql', self::get_setting( 'comment_meta_whitelist' ) ) ) . '\')';
	}

	/**
	 * Returns SQL-escaped values for allowed post meta keys.
	 *
	 * @access public
	 * @static
	 *
	 * @return array Meta keys filter values
	 */
	public static function get_allowed_comment_meta_structured() {
		return array(
			'meta_key' => array(
				'operator' => 'IN',
				'values'   => array_map( 'esc_sql', self::get_setting( 'comment_meta_whitelist' ) ),
			),
		);
	}

	/**
	 * Returns SQL-escaped values for allowed order_item meta keys.
	 *
	 * @access public
	 * @static
	 *
	 * @return array Meta keys filter values
	 */
	public static function get_allowed_order_itemmeta_structured() {
		// Make sure that we only try to add the properties when the class exists.
		if ( ! class_exists( '\Automattic\Jetpack\Sync\Modules\WooCommerce' ) ) {
			return array();
		}

		$values = \Automattic\Jetpack\Sync\Modules\WooCommerce::$order_item_meta_whitelist;

		return array(
			'meta_key' => array(
				'operator' => 'IN',
				'values'   => array_map( 'esc_sql', $values ),
			),
		);
	}

	/**
	 * Returns escaped SQL for comments, excluding any spam comments.
	 * Can be injected directly into a WHERE clause.
	 *
	 * @access public
	 * @static
	 *
	 * @return string SQL WHERE clause.
	 */
	public static function get_comments_filter_sql() {
		return "comment_approved <> 'spam'";
	}

	/**
	 * Delete any settings options and clean up the current settings state.
	 *
	 * @access public
	 * @static
	 */
	public static function reset_data() {
		$valid_settings = self::$valid_settings;
		foreach ( $valid_settings as $option => $value ) {
			delete_option( self::SETTINGS_OPTION_PREFIX . $option );
		}
		self::set_importing( null );
		self::set_doing_cron( null );
		self::set_is_syncing( null );
		self::set_is_sending( null );
	}

	/**
	 * Set the importing state.
	 *
	 * @access public
	 * @static
	 *
	 * @param boolean $is_importing Whether WordPress is currently importing.
	 */
	public static function set_importing( $is_importing ) {
		// Set to NULL to revert to WP_IMPORTING, the standard behavior.
		self::$is_importing = $is_importing;
	}

	/**
	 * Whether WordPress is currently importing.
	 *
	 * @access public
	 * @static
	 *
	 * @return boolean Whether WordPress is currently importing.
	 */
	public static function is_importing() {
		if ( self::$is_importing !== null ) {
			return self::$is_importing;
		}

		return defined( 'WP_IMPORTING' ) && WP_IMPORTING;
	}

	/**
	 * Whether sync is enabled.
	 *
	 * @access public
	 * @static
	 *
	 * @return boolean Whether sync is enabled.
	 */
	public static function is_sync_enabled() {
		return ! ( self::get_setting( 'disable' ) || self::get_setting( 'network_disable' ) );
	}

	/**
	 * Set the WP cron state.
	 *
	 * @access public
	 * @static
	 *
	 * @param boolean $is_doing_cron Whether WordPress is currently doing WP cron.
	 */
	public static function set_doing_cron( $is_doing_cron ) {
		// Set to NULL to revert to WP_IMPORTING, the standard behavior.
		self::$is_doing_cron = $is_doing_cron;
	}

	/**
	 * Whether WordPress is currently doing WP cron.
	 *
	 * @access public
	 * @static
	 *
	 * @return boolean Whether WordPress is currently doing WP cron.
	 */
	public static function is_doing_cron() {
		if ( self::$is_doing_cron !== null ) {
			return self::$is_doing_cron;
		}

		return defined( 'DOING_CRON' ) && DOING_CRON;
	}

	/**
	 * Whether we are currently syncing.
	 *
	 * @access public
	 * @static
	 *
	 * @return boolean Whether we are currently syncing.
	 */
	public static function is_syncing() {
		return (bool) self::$is_syncing || ( defined( 'REST_API_REQUEST' ) && REST_API_REQUEST );
	}

	/**
	 * Set the syncing state.
	 *
	 * @access public
	 * @static
	 *
	 * @param boolean $is_syncing Whether we are currently syncing.
	 */
	public static function set_is_syncing( $is_syncing ) {
		self::$is_syncing = $is_syncing;
	}

	/**
	 * Whether we are currently sending sync items.
	 *
	 * @access public
	 * @static
	 *
	 * @return boolean Whether we are currently sending sync items.
	 */
	public static function is_sending() {
		return (bool) self::$is_sending;
	}

	/**
	 * Set the sending state.
	 *
	 * @access public
	 * @static
	 *
	 * @param boolean $is_sending Whether we are currently sending sync items.
	 */
	public static function set_is_sending( $is_sending ) {
		self::$is_sending = $is_sending;
	}

	/**
	 * Whether should send from the queue
	 *
	 * @access public
	 * @static
	 *
	 * @param string $queue_id The queue identifier.
	 *
	 * @return boolean Whether sync is enabled.
	 */
	public static function is_sender_enabled( $queue_id ) {
		return (bool) self::get_setting( $queue_id . '_sender_enabled' );
	}

	/**
	 * Whether checksums are enabled.
	 *
	 * @access public
	 * @static
	 *
	 * @return boolean Whether sync is enabled.
	 */
	public static function is_checksum_enabled() {
		return ! (bool) self::get_setting( 'checksum_disable' );
	}

	/**
	 * Whether dedicated Sync flow is enabled.
	 *
	 * @access public
	 * @static
	 *
	 * @return boolean Whether dedicated Sync flow is enabled.
	 */
	public static function is_dedicated_sync_enabled() {
		return (bool) self::get_setting( 'dedicated_sync_enabled' );
	}

}
