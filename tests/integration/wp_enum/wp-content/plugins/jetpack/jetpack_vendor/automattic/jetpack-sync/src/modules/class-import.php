<?php
/**
 * Import sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

use Automattic\Jetpack\Sync\Settings;

/**
 * Class to handle sync for imports.
 */
class Import extends Module {

	/**
	 * Tracks which actions have already been synced for the import
	 * to prevent the same event from being triggered a second time.
	 *
	 * @var array
	 */
	private $synced_actions = array();

	/**
	 * A mapping of action types to sync action name.
	 * Keys are the name of the import action.
	 * Values are the resulting sync action.
	 *
	 * Note: import_done and import_end both intentionally map to
	 * jetpack_sync_import_end, as they both track the same type of action,
	 * the successful completion of an import. Different import plugins use
	 * differently named actions, and this is an attempt to consolidate.
	 *
	 * @var array
	 */
	private static $import_sync_action_map = array(
		'import_start' => 'jetpack_sync_import_start',
		'import_done'  => 'jetpack_sync_import_end',
		'import_end'   => 'jetpack_sync_import_end',
	);

	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'import';
	}

	/**
	 * Initialize imports action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_listeners( $callable ) {
		add_action( 'export_wp', $callable );
		add_action( 'jetpack_sync_import_start', $callable, 10, 2 );
		add_action( 'jetpack_sync_import_end', $callable, 10, 2 );

		// WordPress.
		add_action( 'import_start', array( $this, 'sync_import_action' ) );

		// Movable type, RSS, Livejournal.
		add_action( 'import_done', array( $this, 'sync_import_action' ) );

		// WordPress, Blogger, Livejournal, woo tax rate.
		add_action( 'import_end', array( $this, 'sync_import_action' ) );
	}

	/**
	 * Set module defaults.
	 * Define an empty list of synced actions for us to fill later.
	 *
	 * @access public
	 */
	public function set_defaults() {
		$this->synced_actions = array();
	}

	/**
	 * Generic handler for import actions.
	 *
	 * @access public
	 *
	 * @param string $importer Either a string reported by the importer, the class name of the importer, or 'unknown'.
	 */
	public function sync_import_action( $importer ) {
		$import_action = current_filter();
		// Map action to event name.
		$sync_action = self::$import_sync_action_map[ $import_action ];

		// Only sync each action once per import.
		if ( array_key_exists( $sync_action, $this->synced_actions ) && $this->synced_actions[ $sync_action ] ) {
			return;
		}

		// Mark this action as synced.
		$this->synced_actions[ $sync_action ] = true;

		// Prefer self-reported $importer value.
		if ( ! $importer ) {
			// Fall back to inferring by calling class name.
			$importer = self::get_calling_importer_class();
		}

		// Get $importer from known_importers.
		$known_importers = Settings::get_setting( 'known_importers' );
		if ( is_string( $importer ) && isset( $known_importers[ $importer ] ) ) {
			$importer = $known_importers[ $importer ];
		}

		$importer_name = $this->get_importer_name( $importer );

		switch ( $sync_action ) {
			case 'jetpack_sync_import_start':
				/**
				 * Used for syncing the start of an import
				 *
				 * @since 1.6.3
				 * @since-jetpack 7.3.0
				 *
				 * @module sync
				 *
				 * @param string $importer      Either a string reported by the importer, the class name of the importer, or 'unknown'.
				 * @param string $importer_name The name reported by the importer, or 'Unknown Importer'.
				 */
				do_action( 'jetpack_sync_import_start', $importer, $importer_name );
				break;

			case 'jetpack_sync_import_end':
				/**
				 * Used for syncing the end of an import
				 *
				 * @since 1.6.3
				 * @since-jetpack 7.3.0
				 *
				 * @module sync
				 *
				 * @param string $importer      Either a string reported by the importer, the class name of the importer, or 'unknown'.
				 * @param string $importer_name The name reported by the importer, or 'Unknown Importer'.
				 */
				do_action( 'jetpack_sync_import_end', $importer, $importer_name );
				break;
		}
	}

	/**
	 * Retrieve the name of the importer.
	 *
	 * @access private
	 *
	 * @param string $importer Either a string reported by the importer, the class name of the importer, or 'unknown'.
	 * @return string Name of the importer, or "Unknown Importer" if importer is unknown.
	 */
	private function get_importer_name( $importer ) {
		$importers = get_importers();
		return isset( $importers[ $importer ] ) ? $importers[ $importer ][0] : 'Unknown Importer';
	}

	/**
	 * Determine the class that extends `WP_Importer` which is responsible for
	 * the current action. Designed to be used within an action handler.
	 *
	 * @access private
	 * @static
	 *
	 * @return string The name of the calling class, or 'unknown'.
	 */
	private static function get_calling_importer_class() {
		// If WP_Importer doesn't exist, neither will any importer that extends it.
		if ( ! class_exists( 'WP_Importer', false ) ) {
			return 'unknown';
		}

		$action    = current_filter();
		$backtrace = debug_backtrace( false ); //phpcs:ignore PHPCompatibility.FunctionUse.NewFunctionParameters.debug_backtrace_optionsFound,WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace

		$do_action_pos = -1;
		$backtrace_len = count( $backtrace );
		for ( $i = 0; $i < $backtrace_len; $i++ ) {
			// Find the location in the stack of the calling action.
			if ( 'do_action' === $backtrace[ $i ]['function'] && $action === $backtrace[ $i ]['args'][0] ) {
				$do_action_pos = $i;
				break;
			}
		}

		// If the action wasn't called, the calling class is unknown.
		if ( -1 === $do_action_pos ) {
			return 'unknown';
		}

		// Continue iterating the stack looking for a caller that extends WP_Importer.
		for ( $i = $do_action_pos + 1; $i < $backtrace_len; $i++ ) {
			// If there is no class on the trace, continue.
			if ( ! isset( $backtrace[ $i ]['class'] ) ) {
				continue;
			}

			$class_name = $backtrace[ $i ]['class'];

			// Check if the class extends WP_Importer.
			if ( class_exists( $class_name, false ) ) {
				$parents = class_parents( $class_name, false );
				if ( $parents && in_array( 'WP_Importer', $parents, true ) ) {
					return $class_name;
				}
			}
		}

		// If we've exhausted the stack without a match, the calling class is unknown.
		return 'unknown';
	}
}
