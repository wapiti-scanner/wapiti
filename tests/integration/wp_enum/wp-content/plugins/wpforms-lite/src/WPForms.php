<?php

namespace WPForms {

	use AllowDynamicProperties;
	use stdClass;

	/**
	 * Main WPForms class.
	 *
	 * @since 1.0.0
	 */
	#[AllowDynamicProperties]
	final class WPForms {

		/**
		 * One is the loneliest number that you'll ever do.
		 *
		 * @since 1.0.0
		 *
		 * @var \WPForms\WPForms
		 */
		private static $instance;

		/**
		 * Plugin version for enqueueing, etc.
		 * The value is got from WPFORMS_VERSION constant.
		 *
		 * @since 1.0.0
		 *
		 * @var string
		 */
		public $version = '';

		/**
		 * Classes registry.
		 *
		 * @since 1.5.7
		 *
		 * @var array
		 */
		private $registry = [];

		/**
		 * List of legacy public properties.
		 *
		 * @since 1.6.8
		 *
		 * @var string[]
		 */
		private $legacy_properties = [
			'form',
			'entry',
			'entry_fields',
			'entry_meta',
			'frontend',
			'process',
			'smart_tags',
			'license',
		];

		/**
		 * Paid returns true, free (Lite) returns false.
		 *
		 * @since 1.3.9
		 * @since 1.7.3 changed to private.
		 *
		 * @var bool
		 */
		private $pro = false;

		/**
		 * Backward compatibility method for accessing the class registry in an old way,
		 * e.g. 'wpforms()->form' or 'wpforms()->entry'.
		 *
		 * @since 1.5.7
		 *
		 * @param string $name Name of the object to get.
		 *
		 * @return mixed|null
		 */
		public function __get( $name ) {

			if ( $name === 'smart_tags' ) {
				_deprecated_argument(
					'wpforms()->smart_tags',
					'1.6.7 of the WPForms plugin',
					"Please use `wpforms()->get( 'smart_tags' )` instead."
				);
			}

			if ( $name === 'pro' ) {
				return wpforms()->is_pro();
			}

			return $this->get( $name );
		}

		/**
		 * Main WPForms Instance.
		 *
		 * Only one instance of WPForms exists in memory at any one time.
		 * Also prevent the need to define globals all over the place.
		 *
		 * @since 1.0.0
		 *
		 * @return WPForms
		 */
		public static function instance() {

			if (
				self::$instance === null ||
				! self::$instance instanceof self
			) {

				self::$instance = new self();

				self::$instance->constants();
				self::$instance->includes();

				// Load Pro or Lite specific files.
				if ( self::$instance->is_pro() ) {
					self::$instance->registry['pro'] = require_once WPFORMS_PLUGIN_DIR . 'pro/wpforms-pro.php';
				} else {
					require_once WPFORMS_PLUGIN_DIR . 'lite/wpforms-lite.php';
				}

				add_action( 'plugins_loaded', [ self::$instance, 'objects' ], 10 );
			}

			return self::$instance;
		}

		/**
		 * Setup plugin constants.
		 * All the path/URL related constants are defined in main plugin file.
		 *
		 * @since 1.0.0
		 */
		private function constants() {

			$this->version = WPFORMS_VERSION;

			// Plugin Slug - Determine plugin type and set slug accordingly.
			// This filter is documented in \WPForms\WPForms::is_pro.
			if ( apply_filters( 'wpforms_allow_pro_version', file_exists( WPFORMS_PLUGIN_DIR . 'pro/wpforms-pro.php' ) ) ) {
				$this->pro = true;

				define( 'WPFORMS_PLUGIN_SLUG', 'wpforms' );
			} else {
				define( 'WPFORMS_PLUGIN_SLUG', 'wpforms-lite' );
			}
		}

		/**
		 * Include files.
		 *
		 * @since 1.0.0
		 */
		private function includes() {

			require_once WPFORMS_PLUGIN_DIR . 'includes/class-db.php';
			require_once WPFORMS_PLUGIN_DIR . 'includes/functions.php';
			require_once WPFORMS_PLUGIN_DIR . 'includes/compat.php';

			$this->includes_magic();

			// Global includes.
			require_once WPFORMS_PLUGIN_DIR . 'includes/class-install.php';
			require_once WPFORMS_PLUGIN_DIR . 'includes/class-form.php';
			require_once WPFORMS_PLUGIN_DIR . 'includes/class-fields.php';
			// TODO: class-templates.php should be loaded in admin area only.
			require_once WPFORMS_PLUGIN_DIR . 'includes/class-templates.php';
			// TODO: class-providers.php should be loaded in admin area only.
			require_once WPFORMS_PLUGIN_DIR . 'includes/class-providers.php';
			require_once WPFORMS_PLUGIN_DIR . 'includes/class-process.php';
			require_once WPFORMS_PLUGIN_DIR . 'includes/class-widget.php';
			require_once WPFORMS_PLUGIN_DIR . 'includes/emails/class-emails.php';
			require_once WPFORMS_PLUGIN_DIR . 'includes/integrations.php';
			require_once WPFORMS_PLUGIN_DIR . 'includes/deprecated.php';

			// Admin/Dashboard only includes, also in ajax.
			if ( is_admin() ) {
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/admin.php';
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/class-notices.php';
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/class-menu.php';
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/overview/class-overview.php';
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/builder/class-builder.php';
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/builder/functions.php';
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/class-settings.php';
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/class-welcome.php';
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/class-editor.php';
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/class-review.php';
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/class-about.php';
				require_once WPFORMS_PLUGIN_DIR . 'includes/admin/ajax-actions.php';
			}
		}

		/**
		 * Including the new files with PHP 5.3 style.
		 *
		 * @since 1.4.7
		 */
		private function includes_magic() {

			// Action Scheduler requires a special loading procedure.
			require_once WPFORMS_PLUGIN_DIR . 'vendor/woocommerce/action-scheduler/action-scheduler.php';

			// Autoload Composer packages.
			require_once WPFORMS_PLUGIN_DIR . 'vendor/autoload.php';

			// Load the class loader.
			$this->register(
				[
					'name' => 'Loader',
					'hook' => false,
				]
			);

			/*
			 * Load email subsystem.
			 */
			add_action( 'wpforms_loaded', [ '\WPForms\Emails\Summaries', 'get_instance' ] );

			/*
			 * Load admin components. Exclude from frontend.
			 */
			if ( is_admin() ) {
				add_action( 'wpforms_loaded', [ '\WPForms\Admin\Loader', 'get_instance' ] );
			}

			/*
			 * Properly init the providers loader, that will handle all the related logic and further loading.
			 */
			add_action( 'wpforms_loaded', [ '\WPForms\Providers\Providers', 'get_instance' ] );

			/*
			 * Properly init the integrations loader, that will handle all the related logic and further loading.
			 */
			add_action( 'wpforms_loaded', [ '\WPForms\Integrations\Loader', 'get_instance' ] );
		}

		/**
		 * Setup objects.
		 *
		 * @since 1.0.0
		 */
		public function objects() {

			// Global objects.
			$this->form    = new \WPForms_Form_Handler();
			$this->process = new \WPForms_Process();

			/**
			 * Executes when all the WPForms stuff was loaded.
			 *
			 * @since 1.4.0
			 */
			do_action( 'wpforms_loaded' );
		}

		/**
		 * Register a class.
		 *
		 * @since 1.5.7
		 *
		 * @param array $class Class registration info.
		 */
		public function register( $class ) {

			if ( empty( $class['name'] ) || ! is_string( $class['name'] ) ) {
				return;
			}

			if ( isset( $class['condition'] ) && empty( $class['condition'] ) ) {
				return;
			}

			$full_name = $this->is_pro() ? '\WPForms\Pro\\' . $class['name'] : '\WPForms\Lite\\' . $class['name'];
			$full_name = class_exists( $full_name ) ? $full_name : '\WPForms\\' . $class['name'];

			if ( ! class_exists( $full_name ) ) {
				return;
			}

			$id       = isset( $class['id'] ) ? $class['id'] : '';
			$id       = $id ? preg_replace( '/[^a-z_]/', '', (string) $id ) : $id;
			$hook     = isset( $class['hook'] ) ? (string) $class['hook'] : 'wpforms_loaded';
			$run      = isset( $class['run'] ) ? $class['run'] : 'init';
			$priority = isset( $class['priority'] ) && is_int( $class['priority'] ) ? $class['priority'] : 10;

			$callback = function () use ( $full_name, $id, $run ) {

				$instance = new $full_name();

				if ( $id && ! array_key_exists( $id, $this->registry ) ) {
					$this->registry[ $id ] = $instance;
				}
				if ( $run && method_exists( $instance, $run ) ) {
					$instance->{$run}();
				}
			};

			if ( $hook ) {
				add_action( $hook, $callback, $priority );
			} else {
				$callback();
			}
		}

		/**
		 * Register classes in bulk.
		 *
		 * @since 1.5.7
		 *
		 * @param array $classes Classes to register.
		 */
		public function register_bulk( $classes ) {

			if ( ! is_array( $classes ) ) {
				return;
			}

			foreach ( $classes as $class ) {
				$this->register( $class );
			}
		}

		/**
		 * Get a class instance from a registry.
		 *
		 * @since 1.5.7
		 *
		 * @param string $name Class name or an alias.
		 *
		 * @return mixed|stdClass|null
		 */
		public function get( $name ) {

			if ( ! empty( $this->registry[ $name ] ) ) {
				return $this->registry[ $name ];
			}

			// Backward compatibility for old public properties.
			// Return null to save old condition for these properties.
			if ( in_array( $name, $this->legacy_properties, true ) ) {
				return isset( $this->{$name} ) ? $this->{$name} : null;
			}

			return new stdClass();
		}

		/**
		 * Get the list of all custom tables starting with `wpforms_*`.
		 *
		 * @since 1.6.3
		 *
		 * @return array List of table names.
		 */
		public function get_existing_custom_tables() {

			global $wpdb;

			$tables = $wpdb->get_results( "SHOW TABLES LIKE '" . $wpdb->prefix . "wpforms_%'", 'ARRAY_N' ); // phpcs:ignore

			return ! empty( $tables ) ? wp_list_pluck( $tables, 0 ) : [];
		}

		/**
		 * Whether the current instance of the plugin is a paid version, or free.
		 *
		 * @since 1.7.3
		 *
		 * @return bool
		 */
		public function is_pro() {

			/**
			 * Filters whether the current plugin version is pro.
			 *
			 * @since 1.7.3
			 *
			 * @param bool $pro Whether the current plugin version is pro.
			 */
			return (bool) apply_filters( 'wpforms_allow_pro_version', $this->pro );
		}
	}
}

namespace {

	/**
	 * The function which returns the one WPForms instance.
	 *
	 * @since 1.0.0
	 *
	 * @return WPForms\WPForms
	 */
	function wpforms() {

		return WPForms\WPForms::instance();
	}

	/**
	 * Adding an alias for backward-compatibility with plugins
	 * that still use class_exists( 'WPForms' )
	 * instead of function_exists( 'wpforms' ), which is preferred.
	 *
	 * In 1.5.0 we removed support for PHP 5.2
	 * and moved former WPForms class to a namespace: WPForms\WPForms.
	 *
	 * @since 1.5.1
	 */
	class_alias( 'WPForms\WPForms', 'WPForms' );
}
