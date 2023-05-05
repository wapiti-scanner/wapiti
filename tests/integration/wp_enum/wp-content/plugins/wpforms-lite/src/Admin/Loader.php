<?php

namespace WPForms\Admin;

/**
 * Class Loader gives ability to track/load all admin modules.
 *
 * @since 1.5.0
 */
class Loader {

	/**
	 * Get the instance of a class and store it in itself.
	 *
	 * @since 1.5.0
	 */
	public static function get_instance() {

		static $instance;

		if ( ! $instance ) {
			$instance = new self();
		}

		return $instance;
	}

	/**
	 * Loader constructor.
	 *
	 * @since 1.5.0
	 */
	public function __construct() {

		$core_class_names = [
			'Connect',
			'DashboardWidget',
			'FlyoutMenu',
			'Builder\LicenseAlert',
			'Builder\Builder',
			'Pages\Community',
			'Pages\SMTP',
			'Pages\Analytics',
			'Entries\PrintPreview',
			'Entries\DefaultScreen',
		];

		$class_names = \apply_filters( 'wpforms_admin_classes_available', $core_class_names );

		foreach ( $class_names as $class_name ) {
			$this->register_class( $class_name );
		}
	}

	/**
	 * Register a new class.
	 *
	 * @since 1.5.0
	 *
	 * @param string $class_name Class name to register.
	 */
	public function register_class( $class_name ) {

		$class_name = sanitize_text_field( $class_name );

		// Load Lite class if exists.
		if ( class_exists( 'WPForms\Lite\Admin\\' . $class_name ) && ! wpforms()->is_pro() ) {
			$class_name = 'WPForms\Lite\Admin\\' . $class_name;

			new $class_name();

			return;
		}

		// Load Pro class if exists.
		if ( class_exists( 'WPForms\Pro\Admin\\' . $class_name ) && wpforms()->is_pro() ) {
			$class_name = 'WPForms\Pro\Admin\\' . $class_name;

			new $class_name();

			return;
		}

		// Load general class if neither Pro nor Lite class exists.
		if ( class_exists( __NAMESPACE__ . '\\' . $class_name ) ) {
			$class_name = __NAMESPACE__ . '\\' . $class_name;

			new $class_name();
		}
	}
}
