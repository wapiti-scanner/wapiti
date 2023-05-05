<?php
/**
 * Updates sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

use Automattic\Jetpack\Constants as Jetpack_Constants;

/**
 * Class to handle sync for updates.
 */
class Updates extends Module {
	/**
	 * Name of the updates checksum option.
	 *
	 * @var string
	 */
	const UPDATES_CHECKSUM_OPTION_NAME = 'jetpack_updates_sync_checksum';

	/**
	 * WordPress Version.
	 *
	 * @access private
	 *
	 * @var string
	 */
	private $old_wp_version = null;

	/**
	 * The current updates.
	 *
	 * @access private
	 *
	 * @var array
	 */
	private $updates = array();

	/**
	 * Set module defaults.
	 *
	 * @access public
	 */
	public function set_defaults() {
		$this->updates = array();
	}

	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'updates';
	}

	/**
	 * Initialize updates action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_listeners( $callable ) {
		global $wp_version;
		$this->old_wp_version = $wp_version;
		add_action( 'set_site_transient_update_plugins', array( $this, 'validate_update_change' ), 10, 3 );
		add_action( 'set_site_transient_update_themes', array( $this, 'validate_update_change' ), 10, 3 );
		add_action( 'set_site_transient_update_core', array( $this, 'validate_update_change' ), 10, 3 );

		add_action( 'jetpack_update_plugins_change', $callable );
		add_action( 'jetpack_update_themes_change', $callable );
		add_action( 'jetpack_update_core_change', $callable );

		add_filter(
			'jetpack_sync_before_enqueue_jetpack_update_plugins_change',
			array(
				$this,
				'filter_update_keys',
			),
			10,
			2
		);
		add_filter(
			'jetpack_sync_before_enqueue_upgrader_process_complete',
			array(
				$this,
				'filter_upgrader_process_complete',
			),
			10,
			2
		);

		add_action( 'automatic_updates_complete', $callable );

		if ( is_multisite() ) {
			add_filter( 'pre_update_site_option_wpmu_upgrade_site', array( $this, 'update_core_network_event' ), 10, 2 );
			add_action( 'jetpack_sync_core_update_network', $callable, 10, 3 );
		}

		// Send data when update completes.
		add_action( '_core_updated_successfully', array( $this, 'update_core' ) );
		add_action( 'jetpack_sync_core_reinstalled_successfully', $callable );
		add_action( 'jetpack_sync_core_autoupdated_successfully', $callable, 10, 2 );
		add_action( 'jetpack_sync_core_updated_successfully', $callable, 10, 2 );
	}

	/**
	 * Initialize updates action listeners for full sync.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_full_sync_listeners( $callable ) {
		add_action( 'jetpack_full_sync_updates', $callable );
	}

	/**
	 * Initialize the module in the sender.
	 *
	 * @access public
	 */
	public function init_before_send() {
		add_filter( 'jetpack_sync_before_send_jetpack_full_sync_updates', array( $this, 'expand_updates' ) );
		add_filter( 'jetpack_sync_before_send_jetpack_update_themes_change', array( $this, 'expand_themes' ) );
	}

	/**
	 * Handle a core network update.
	 *
	 * @access public
	 *
	 * @param int $wp_db_version     Current version of the WordPress database.
	 * @param int $old_wp_db_version Old version of the WordPress database.
	 * @return int Current version of the WordPress database.
	 */
	public function update_core_network_event( $wp_db_version, $old_wp_db_version ) {
		global $wp_version;
		/**
		 * Sync event for when core wp network updates to a new db version
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.0.0
		 *
		 * @param int $wp_db_version the latest wp_db_version
		 * @param int $old_wp_db_version previous wp_db_version
		 * @param string $wp_version the latest wp_version
		 */
		do_action( 'jetpack_sync_core_update_network', $wp_db_version, $old_wp_db_version, $wp_version );
		return $wp_db_version;
	}

	/**
	 * Handle a core update.
	 *
	 * @access public
	 *
	 * @todo Implement nonce or refactor to use `admin_post_{$action}` hooks instead.
	 *
	 * @param string $new_wp_version The new WP core version.
	 */
	public function update_core( $new_wp_version ) {
		global $pagenow;

		// // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['action'] ) && 'do-core-reinstall' === $_GET['action'] ) {
			/**
			 * Sync event that fires when core reinstall was successful
			 *
			 * @since 1.6.3
			 * @since-jetpack 5.0.0
			 *
			 * @param string $new_wp_version the updated WordPress version
			 */
			do_action( 'jetpack_sync_core_reinstalled_successfully', $new_wp_version );
			return;
		}

		// Core was autoupdated.
		if (
			'update-core.php' !== $pagenow &&
			! Jetpack_Constants::is_true( 'REST_API_REQUEST' ) // WP.com rest api calls should never be marked as a core autoupdate.
		) {
			/**
			 * Sync event that fires when core autoupdate was successful
			 *
			 * @since 1.6.3
			 * @since-jetpack 5.0.0
			 *
			 * @param string $new_wp_version the updated WordPress version
			 * @param string $old_wp_version the previous WordPress version
			 */
			do_action( 'jetpack_sync_core_autoupdated_successfully', $new_wp_version, $this->old_wp_version );
			return;
		}
		/**
		 * Sync event that fires when core update was successful
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.0.0
		 *
		 * @param string $new_wp_version the updated WordPress version
		 * @param string $old_wp_version the previous WordPress version
		 */
		do_action( 'jetpack_sync_core_updated_successfully', $new_wp_version, $this->old_wp_version );
	}

	/**
	 * Retrieve the checksum for an update.
	 *
	 * @access public
	 *
	 * @param object $update    The update object.
	 * @param string $transient The transient we're retrieving a checksum for.
	 * @return int The checksum.
	 */
	public function get_update_checksum( $update, $transient ) {
		$updates    = array();
		$no_updated = array();
		switch ( $transient ) {
			case 'update_plugins':
				if ( ! empty( $update->response ) && is_array( $update->response ) ) {
					foreach ( $update->response as $plugin_slug => $response ) {
						if ( ! empty( $plugin_slug ) && isset( $response->new_version ) ) {
							$updates[] = array( $plugin_slug => $response->new_version );
						}
					}
				}
				if ( ! empty( $update->no_update ) ) {
					$no_updated = array_keys( $update->no_update );
				}

				if ( ! isset( $no_updated['jetpack/jetpack.php'] ) && isset( $updates['jetpack/jetpack.php'] ) ) {
					return false;
				}

				break;
			case 'update_themes':
				if ( ! empty( $update->response ) && is_array( $update->response ) ) {
					foreach ( $update->response as $theme_slug => $response ) {
						if ( ! empty( $theme_slug ) && isset( $response['new_version'] ) ) {
							$updates[] = array( $theme_slug => $response['new_version'] );
						}
					}
				}

				if ( ! empty( $update->checked ) ) {
					$no_updated = $update->checked;
				}

				break;
			case 'update_core':
				if ( ! empty( $update->updates ) && is_array( $update->updates ) ) {
					foreach ( $update->updates as $response ) {
						if ( ! empty( $response->response ) && 'latest' === $response->response ) {
							continue;
						}
						if ( ! empty( $response->response ) && isset( $response->packages->full ) ) {
							$updates[] = array( $response->response => $response->packages->full );
						}
					}
				}

				if ( ! empty( $update->version_checked ) ) {
					$no_updated = $update->version_checked;
				}

				if ( empty( $updates ) ) {
					return false;
				}
				break;

		}
		if ( empty( $updates ) && empty( $no_updated ) ) {
			return false;
		}
		return $this->get_check_sum( array( $no_updated, $updates ) );
	}

	/**
	 * Validate a change coming from an update before sending for sync.
	 *
	 * @access public
	 *
	 * @param mixed  $value      Site transient value.
	 * @param int    $expiration Time until transient expiration in seconds.
	 * @param string $transient  Transient name.
	 */
	public function validate_update_change( $value, $expiration, $transient ) {
		$new_checksum = $this->get_update_checksum( $value, $transient );

		if ( false === $new_checksum ) {
			return;
		}

		$checksums = get_option( self::UPDATES_CHECKSUM_OPTION_NAME, array() );

		if ( isset( $checksums[ $transient ] ) && $checksums[ $transient ] === $new_checksum ) {
			return;
		}

		$checksums[ $transient ] = $new_checksum;

		update_option( self::UPDATES_CHECKSUM_OPTION_NAME, $checksums );
		if ( 'update_core' === $transient ) {
			/**
			 * Trigger a change to core update that we want to sync.
			 *
			 * @since 1.6.3
			 * @since-jetpack 5.1.0
			 *
			 * @param array $value Contains info that tells us what needs updating.
			 */
			do_action( 'jetpack_update_core_change', $value );
			return;
		}
		if ( empty( $this->updates ) ) {
			// Lets add the shutdown method once and only when the updates move from empty to filled with something.
			add_action( 'shutdown', array( $this, 'sync_last_event' ), 9 );
		}
		if ( ! isset( $this->updates[ $transient ] ) ) {
			$this->updates[ $transient ] = array();
		}
		$this->updates[ $transient ][] = $value;
	}

	/**
	 * Sync the last update only.
	 *
	 * @access public
	 */
	public function sync_last_event() {
		foreach ( $this->updates as $transient => $values ) {
			$value = end( $values ); // Only send over the last value.
			/**
			 * Trigger a change to a specific update that we want to sync.
			 * Triggers one of the following actions:
			 * - jetpack_{$transient}_change
			 * - jetpack_update_plugins_change
			 * - jetpack_update_themes_change
			 *
			 * @since 1.6.3
			 * @since-jetpack 5.1.0
			 *
			 * @param array $value Contains info that tells us what needs updating.
			 */
			do_action( "jetpack_{$transient}_change", $value );
		}
	}

	/**
	 * Enqueue the updates actions for full sync.
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
		 * Tells the client to sync all updates to the server
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.2.0
		 *
		 * @param boolean Whether to expand updates (should always be true)
		 */
		do_action( 'jetpack_full_sync_updates', true );

		// The number of actions enqueued, and next module state (true == done).
		return array( 1, true );
	}

	/**
	 * Send the updates actions for full sync.
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
		$this->send_action( 'jetpack_full_sync_updates', array( true ) );

		// The number of actions enqueued, and next module state (true == done).
		return array( 'finished' => true );
	}

	/**
	 * Retrieve an estimated number of actions that will be enqueued.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return array Number of items yet to be enqueued.
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
		return array( 'jetpack_full_sync_updates' );
	}

	/**
	 * Retrieve all updates that we're interested in.
	 *
	 * @access public
	 *
	 * @return array All updates.
	 */
	public function get_all_updates() {
		return array(
			'core'    => get_site_transient( 'update_core' ),
			'plugins' => get_site_transient( 'update_plugins' ),
			'themes'  => get_site_transient( 'update_themes' ),
		);
	}

	/**
	 * Remove unnecessary keys from synced updates data.
	 *
	 * @access public
	 *
	 * @param array $args Hook arguments.
	 * @return array $args Hook arguments.
	 */
	public function filter_update_keys( $args ) {
		$updates = $args[0];

		if ( isset( $updates->no_update ) ) {
			unset( $updates->no_update );
		}

		return $args;
	}

	/**
	 * Filter out upgrader object from the completed upgrader action args.
	 *
	 * @access public
	 *
	 * @param array $args Hook arguments.
	 * @return array $args Filtered hook arguments.
	 */
	public function filter_upgrader_process_complete( $args ) {
		array_shift( $args );

		return $args;
	}

	/**
	 * Expand the updates within a hook before they are serialized and sent to the server.
	 *
	 * @access public
	 *
	 * @param array $args The hook parameters.
	 * @return array $args The hook parameters.
	 */
	public function expand_updates( $args ) {
		if ( $args[0] ) {
			return $this->get_all_updates();
		}

		return $args;
	}

	/**
	 * Expand the themes within a hook before they are serialized and sent to the server.
	 *
	 * @access public
	 *
	 * @param array $args The hook parameters.
	 * @return array $args The hook parameters.
	 */
	public function expand_themes( $args ) {
		if ( ! isset( $args[0], $args[0]->response ) ) {
			return $args;
		}
		if ( ! is_array( $args[0]->response ) ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
			trigger_error( 'Warning: Not an Array as expected but -> ' . wp_json_encode( $args[0]->response ) . ' instead', E_USER_WARNING );
			return $args;
		}
		foreach ( $args[0]->response as $stylesheet => &$theme_data ) {
			$theme              = wp_get_theme( $stylesheet );
			$theme_data['name'] = $theme->name;
		}
		return $args;
	}

	/**
	 * Perform module cleanup.
	 * Deletes any transients and options that this module uses.
	 * Usually triggered when uninstalling the plugin.
	 *
	 * @access public
	 */
	public function reset_data() {
		delete_option( self::UPDATES_CHECKSUM_OPTION_NAME );
	}

	/**
	 * Return Total number of objects.
	 *
	 * @param array $config Full Sync config.
	 *
	 * @return int total
	 */
	public function total( $config ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return 3;
	}

	/**
	 * Retrieve a set of updates by their IDs.
	 *
	 * @access public
	 *
	 * @param string $object_type Object type.
	 * @param array  $ids         Object IDs.
	 * @return array Array of objects.
	 */
	public function get_objects_by_id( $object_type, $ids ) {
		if ( empty( $ids ) || empty( $object_type ) || 'update' !== $object_type ) {
			return array();
		}

		$objects = array();
		foreach ( (array) $ids as $id ) {
			$object = $this->get_object_by_id( $object_type, $id );

			if ( 'all' === $id ) {
				// If all was requested it contains all updates and can simply be returned.
				return $object;
			}
			$objects[ $id ] = $object;
		}

		return $objects;
	}

	/**
	 * Retrieve a update by its id.
	 *
	 * @access public
	 *
	 * @param string $object_type Type of the sync object.
	 * @param string $id          ID of the sync object.
	 * @return mixed              Value of Update.
	 */
	public function get_object_by_id( $object_type, $id ) {
		if ( 'update' === $object_type ) {

			// Only whitelisted constants can be returned.
			if ( in_array( $id, array( 'core', 'plugins', 'themes' ), true ) ) {
				return get_site_transient( 'update_' . $id );
			} elseif ( 'all' === $id ) {
				return $this->get_all_updates();
			}
		}

		return false;
	}

}
