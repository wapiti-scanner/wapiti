<?php

namespace WPForms\Migrations;

use ReflectionClass;

/**
 * Class Migrations handles both Lite and Pro plugin upgrade routines.
 *
 * @since 1.7.5
 */
abstract class Base {

	/**
	 * WP option name to store the migration versions.
	 * Must have 'versions' in the name defined in extending classes,
	 * like 'wpforms_versions', 'wpforms_versions_lite, 'wpforms_stripe_versions' etc.
	 *
	 * @since 1.7.5
	 */
	const MIGRATED_OPTION_NAME = '';

	/**
	 * Current plugin version.
	 *
	 * @since 1.7.5
	 */
	const CURRENT_VERSION = WPFORMS_VERSION;

	/**
	 * Name of the core plugin used in log messages.
	 *
	 * @since 1.7.5
	 */
	const PLUGIN_NAME = '';

	/**
	 * Upgrade classes.
	 *
	 * @since 1.7.5
	 */
	const UPGRADE_CLASSES = [];

	/**
	 * Custom table handler classes.
	 *
	 * @since 1.7.6
	 */
	const CUSTOM_TABLE_HANDLER_CLASSES = [];

	/**
	 * Migration started status.
	 *
	 * @since 1.7.5
	 */
	const STARTED = - 1;

	/**
	 * Migration failed status.
	 *
	 * @since 1.7.5
	 */
	const FAILED = - 2;

	/**
	 * Initial fake version for comparisons.
	 *
	 * @since 1.7.5
	 */
	const INITIAL_FAKE_VERSION = '0.0.1';

	/**
	 * Reflection class instance.
	 *
	 * @since 1.7.5
	 *
	 * @var ReflectionClass
	 */
	protected $reflector;

	/**
	 * Migrated versions.
	 *
	 * @since 1.7.5
	 *
	 * @var string[]
	 */
	protected $migrated = [];

	/**
	 * Custom tables.
	 *
	 * @since 1.7.6
	 *
	 * @var array
	 */
	private static $custom_tables;

	/**
	 * Primary class constructor.
	 *
	 * @since 1.7.5
	 */
	public function __construct() {

		$this->reflector = new ReflectionClass( $this );
	}

	/**
	 * Class init.
	 *
	 * @since 1.7.5
	 */
	public function init() {

		if ( ! $this->is_allowed() ) {
			return;
		}

		$this->maybe_create_tables();
		$this->maybe_convert_migration_option();
		$this->hooks();
	}

	/**
	 * General hooks.
	 *
	 * @since 1.7.5
	 */
	protected function hooks() {

		$priority = $this->is_core_plugin() ? - 9999 : 100;

		add_action( 'wpforms_loaded', [ $this, 'migrate' ], $priority );
		add_action( 'wpforms_loaded', [ $this, 'update_versions' ], $priority + 1 );
	}

	/**
	 * Run the migrations of the core plugin for a specific version.
	 *
	 * @since 1.7.5
	 *
	 * @noinspection NotOptimalIfConditionsInspection
	 */
	public function migrate() {

		$classes   = $this->get_upgrade_classes();
		$namespace = $this->reflector->getNamespaceName() . '\\';

		foreach ( $classes as $class ) {
			$upgrade_version = $this->get_upgrade_version( $class );
			$plugin_name     = $this->get_plugin_name( $class );
			$class           = $namespace . $class;

			if (
				( isset( $this->migrated[ $upgrade_version ] ) && $this->migrated[ $upgrade_version ] >= 0 ) ||
				version_compare( $upgrade_version, static::CURRENT_VERSION, '>' ) ||
				! class_exists( $class )
			) {
				continue;
			}

			if ( ! isset( $this->migrated[ $upgrade_version ] ) ) {
				$this->migrated[ $upgrade_version ] = static::STARTED;

				$this->log( sprintf( 'Migration of %1$s to %2$s started.', $plugin_name, $upgrade_version ) );
			}

			// Run upgrade.
			$migrated = ( new $class( $this ) )->run();

			// Some migration methods can be called several times to support AS action,
			// so do not log their completion here.
			if ( $migrated === null ) {
				continue;
			}

			$this->migrated[ $upgrade_version ] = $migrated ? time() : static::FAILED;

			$message = $migrated ?
				sprintf( 'Migration of %1$s to %2$s completed.', $plugin_name, $upgrade_version ) :
				sprintf( 'Migration of %1$s to %2$s failed.', $plugin_name, $upgrade_version );

			$this->log( $message );
		}
	}

	/**
	 * If upgrade has occurred, update versions option in the database.
	 *
	 * @since 1.7.5
	 */
	public function update_versions() {

		// Retrieve the last migrated versions.
		$last_migrated = get_option( static::MIGRATED_OPTION_NAME, [] );
		$migrated      = array_merge( $last_migrated, $this->migrated );

		/**
		 * Store current version upgrade timestamp even if there were no migrations to it.
		 * We need it in wpforms_get_upgraded_timestamp() for further usage in Event Driven Plugin Notifications.
		 */
		$migrated[ static::CURRENT_VERSION ] = isset( $migrated[ static::CURRENT_VERSION ] ) ?
			$migrated[ static::CURRENT_VERSION ] :
			time();

		ksort( $last_migrated );
		ksort( $migrated );

		if ( $migrated === $last_migrated ) {
			return;
		}

		update_option( static::MIGRATED_OPTION_NAME, $migrated );

		$fully_completed = array_reduce(
			$migrated,
			static function ( $carry, $status ) {

				return $carry && ( $status >= 0 );
			},
			true
		);

		if ( ! $fully_completed ) {
			return;
		}

		$this->log(
			sprintf( 'Migration of %1$s to %2$s is fully completed.', static::PLUGIN_NAME, static::CURRENT_VERSION )
		);

		// We need to run further only for core plugin (Lite and Pro).
		if ( ! $this->is_core_plugin() ) {
			 return;
		}

		$last_completed = array_filter(
			$last_migrated,
			static function( $status ) {

				return $status >= 0;
			}
		);

		if ( ! $last_completed ) {
			return;
		}

		update_option( 'wpforms_version_upgraded_from', $this->get_max_version( $last_completed ) );
	}

	/**
	 * Get upgrade classes.
	 *
	 * @since 1.7.5
	 *
	 * @return string[]
	 */
	protected function get_upgrade_classes() {

		$classes = static::UPGRADE_CLASSES;

		sort( $classes );

		return $classes;
	}

	/**
	 * Get upgrade version from the class name.
	 *
	 * @since 1.7.5
	 *
	 * @param string $class Class name.
	 *
	 * @return string
	 */
	protected function get_upgrade_version( $class ) {

		// Find only the digits to get version number.
		if ( ! preg_match( '/\d+/', $class, $matches ) ) {
			return '';
		}

		return implode( '.', str_split( $matches[0] ) );
	}

	/**
	 * Get plugin/addon name.
	 *
	 * @since 1.7.5
	 *
	 * @param string $class Upgrade class name.
	 *
	 * @return string
	 */
	protected function get_plugin_name( $class ) {

		return static::PLUGIN_NAME;
	}

	/**
	 * Log message to WPForms logger and standard debug.log file.
	 *
	 * @since 1.7.5
	 *
	 * @param string $message The error message that should be logged.
	 *
	 * @noinspection ForgottenDebugOutputInspection
	 */
	protected function log( $message ) {

		if ( defined( 'WPFORMS_DEBUG' ) && WPFORMS_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( $message );
			wpforms_log( 'Migration', $message, [ 'type' => 'log' ] );
		}
	}

	/**
	 * Determine if migration is allowed.
	 *
	 * @since 1.7.5
	 */
	private function is_allowed() {

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['service-worker'] ) ) {
			return false;
		}

		return ( defined( 'DOING_CRON' ) && DOING_CRON ) || is_admin();
	}

	/**
	 * Maybe create custom plugin tables.
	 *
	 * @since 1.7.6
	 */
	private function maybe_create_tables() {

		if ( self::$custom_tables === null ) {
			self::$custom_tables = wpforms()->get_existing_custom_tables();
		}

		foreach ( static::CUSTOM_TABLE_HANDLER_CLASSES as $custom_table_handler_class ) {
			if ( ! class_exists( $custom_table_handler_class ) ) {
				continue;
			}

			$custom_table_handler = new $custom_table_handler_class();

			if ( ! in_array( $custom_table_handler->table_name, self::$custom_tables, true ) ) {
				$custom_table_handler->create_table();
			}
		}
	}

	/**
	 * Maybe convert migration option format.
	 *
	 * @since 1.7.5
	 */
	private function maybe_convert_migration_option() {

		/**
		 * Retrieve the migration option and check its format.
		 * Old format: a string 'x.y.z' containing last migrated version.
		 * New format: [ 'x.y.z' => {status}, 'x1.y1.z1' => {status}... ],
		 * where {status} is a migration status.
		 * Negative means some status (-1 for 'started' etc.),
		 * zero means completed earlier at unknown time,
		 * positive means completion timestamp.
		 */
		$this->migrated = get_option( static::MIGRATED_OPTION_NAME );

		// If option is an array, it means that it is already converted to the new format.
		if ( is_array( $this->migrated ) ) {
			return;
		}

		/**
		 * Convert option to the new format.
		 *
		 * Old option names contained 'version',
		 * like 'wpforms_version', 'wpforms_version_lite', 'wpforms_stripe_version' etc.
		 * We preserve old options for downgrade cases.
		 * New option names should contain 'versions' and be like 'wpforms_versions' etc.
		 */
		$this->migrated = get_option(
			str_replace( 'versions', 'version', static::MIGRATED_OPTION_NAME )
		);

		$version         = $this->migrated === false ? self::INITIAL_FAKE_VERSION : (string) $this->migrated;
		$timestamp       = $version === static::CURRENT_VERSION ? time() : 0;
		$this->migrated  = [ $version => $timestamp ];
		$max_version     = $this->get_max_version( $this->migrated );
		$upgrade_classes = $this->get_upgrade_classes();

		foreach ( $upgrade_classes as $upgrade_class ) {
			$upgrade_version = $this->get_upgrade_version( $upgrade_class );

			if (
				! isset( $this->migrated[ $upgrade_version ] ) &&
				version_compare( $upgrade_version, $max_version, '<' )
			) {
				$this->migrated[ $upgrade_version ] = 0;
			}
		}

		unset( $this->migrated[ self::INITIAL_FAKE_VERSION ] );

		ksort( $this->migrated );

		update_option( static::MIGRATED_OPTION_NAME, $this->migrated );
	}

	/**
	 * Get max version.
	 *
	 * @since 1.7.5
	 *
	 * @param array $versions Versions.
	 *
	 * @return string
	 */
	private function get_max_version( $versions ) {

		return array_reduce(
			array_keys( $versions ),
			static function( $carry, $version ) {

				return version_compare( $version, $carry, '>' ) ? $version : $carry;
			},
			self::INITIAL_FAKE_VERSION
		);
	}

	/**
	 * Determine if it is the core plugin (Lite or Pro).
	 *
	 * @since 1.7.5
	 *
	 * @return bool True if it is the core plugin.
	 */
	protected function is_core_plugin() {

		return strpos( static::MIGRATED_OPTION_NAME, 'wpforms_versions' ) === 0;
	}
}
