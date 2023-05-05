<?php

// phpcs:ignoreFile Generic.Files.OneObjectStructurePerFile.MultipleFound

namespace WPForms {
	/**
	 * The removed class helps prevent fatal errors for clients
	 * that use some of the classes we are about to remove.
	 * Use the class extending instead of class_alias function.
	 *
	 * @since 1.8.0
	 */
	class Removed {

		/**
		 * List of removed classes in the next format:
		 * Fully-Qualified Class Name => version.
		 *
		 * @since 1.8.0
		 */
		const CLASSES = [];

		/**
		 * Inform clients that the class is removed.
		 *
		 * @since 1.8.0
		 */
		public function __construct() {

			self::trigger_error();
		}

		/**
		 * Inform clients that the class is removed.
		 *
		 * @since 1.8.0
		 *
		 * @param string $name Property name.
		 */
		public function __get( $name ) {

			self::trigger_error( $name );
		}

		/**
		 * Inform clients that the class is removed.
		 *
		 * @since 1.8.0
		 *
		 * @param string $name  Property name.
		 * @param mixed  $value Property value.
		 */
		public function __set( $name, $value ) {

			self::trigger_error( $name );
		}

		/**
		 * Inform clients that the class is removed.
		 *
		 * @since 1.8.0
		 *
		 * @param string $name Property name.
		 */
		public function __isset( $name ) {

			self::trigger_error( $name );
		}


		/**
		 * Inform clients that the class is removed.
		 *
		 * @since 1.8.0
		 *
		 * @param string $name      Method name.
		 * @param array  $arguments List of arguments.
		 */
		public function __call( $name, $arguments ) {

			self::trigger_error( $name );
		}

		/**
		 * Inform clients that the class is removed.
		 *
		 * @since 1.8.0
		 *
		 * @param string $name      Method name.
		 * @param array  $arguments List of arguments.
		 */
		public static function __callStatic( $name, $arguments ) {

			self::trigger_error( $name );
		}

		/**
		 * Inform clients that the class is removed.
		 *
		 * @since 1.8.0
		 *
		 * @param string $element_name Property or method name.
		 */
		private static function trigger_error( $element_name = '' ) {

			$current_class   = static::class;
			$removed_element = $current_class;

			if ( $element_name ) {
				$removed_element .= '::' . $element_name;
			}

			$version = ! empty( self::CLASSES[ $current_class ] ) ? self::CLASSES[ $current_class ] : WPFORMS_VERSION;

			trigger_error(
				sprintf(
					'%1$s has been removed in %2$s of the WPForms plugin',
					esc_html( $removed_element ),
					esc_html( $version )
				),
				E_USER_WARNING
			);
		}
	}
}

namespace WPForms\Forms {

	use WPForms\Removed;

	class Loader extends Removed {}
}

namespace {
	/**
	 * To be compatible with both WP 4.9 (that can run on PHP 5.2+) and WP 5.3+ (PHP 5.6+)
	 * we need to rewrite some core WP classes and tweak our own skins to not use PHP 5.6 splat operator (...$args)
	 * that were introduced in WP 5.3 in \WP_Upgrader_Skin::feedback().
	 * This alias is a safeguard to those developers who decided to use our internal class WPForms_Install_Silent_Skin,
	 * which we deleted.
	 *
	 * @since 1.5.6.1
	 */
	class_alias( 'WPForms\Helpers\PluginSilentUpgraderSkin', 'WPForms_Install_Silent_Skin' );

	/**
	 * Legacy `WPForms_Addons` class was refactored and moved to the new `WPForms\Pro\Admin\Pages\Addons` class.
	 * This alias is a safeguard to those developers who use our internal class WPForms_Addons,
	 * which we deleted.
	 *
	 * @since 1.6.7
	 */
	class_alias( wpforms()->is_pro() ? 'WPForms\Pro\Admin\Pages\Addons' : 'WPForms\Lite\Admin\Pages\Addons', 'WPForms_Addons' );

	/**
	 * This alias is a safeguard to those developers who decided to use our internal class WPForms_Smart_Tags,
	 * which we deleted.
	 *
	 * @since 1.6.7
	 */
	class_alias( wpforms()->is_pro() ? 'WPForms\Pro\SmartTags\SmartTags' : 'WPForms\SmartTags\SmartTags', 'WPForms_Smart_Tags' );

	/**
	 * This alias is a safeguard to those developers who decided to use our internal class \WPForms\Providers\Loader,
	 * which we deleted.
	 *
	 * @since 1.7.3
	 */
	class_alias( '\WPForms\Providers\Providers', '\WPForms\Providers\Loader' );

	/**
	 * Legacy `\WPForms\Admin\Notifications` class was refactored and moved to the new `\WPForms\Admin\Notifications\Notifications` class.
	 * This alias is a safeguard to those developers who use our internal class \WPForms\Admin\Notifications,
	 * which we deleted.
	 *
	 * @since 1.7.5
	 */
	class_alias( '\WPForms\Admin\Notifications\Notifications', '\WPForms\Admin\Notifications' );

	/**
	 * Legacy `\WPForms\Migrations` class was refactored and moved to the new `\WPForms\Migrations\Migrations` class.
	 * This alias is a safeguard to those developers who use our internal class \WPForms\Migrations, which we deleted.
	 *
	 * @since 1.7.5
	 */
	class_alias( '\WPForms\Migrations\Migrations', '\WPForms\Migrations' );

	if ( wpforms()->is_pro() ) {
		/**
		 * Legacy `\WPForms\Pro\Migrations` class was refactored and moved to the new `\WPForms\Pro\Migrations\Migrations` class.
		 * This alias is a safeguard to those developers who use our internal class \WPForms\Migrations, which we deleted.
		 *
		 * @since 1.7.5
		 */
		class_alias( '\WPForms\Pro\Migrations\Migrations', '\WPForms\Pro\Migrations' );
	}

	/**
	 * Legacy `\WPForms_Frontend` class was refactored and moved to the new `\WPForms\Frontend\Frontend` class.
	 * This alias is a safeguard to those developers who use our internal class \WPForms_Frontend, which we deleted.
	 *
	 * @since 1.8.1
	 */
	class_alias( '\WPForms\Frontend\Frontend', '\WPForms_Frontend' );

	/**
	 * Get notification state, whether it's opened or closed.
	 *
	 * @since      1.4.1
	 * @deprecated 1.4.8
	 *
	 * @param int $notification_id Notification ID.
	 *
	 * @param int $form_id         Form ID.
	 *
	 * @return string
	 */
	function wpforms_builder_notification_get_state( $form_id, $notification_id ) {

		_deprecated_function( __FUNCTION__, '1.4.8 of the WPForms addon', 'wpforms_builder_settings_block_get_state()' );

		return wpforms_builder_settings_block_get_state( $form_id, $notification_id, 'notification' );
	}

	/**
	 * Convert bytes to megabytes (or in some cases KB).
	 *
	 * @since      1.0.0
	 * @deprecated 1.6.2
	 *
	 * @param int $bytes Bytes to convert to a readable format.
	 *
	 * @return string
	 */
	function wpforms_size_to_megabytes( $bytes ) {

		_deprecated_function( __FUNCTION__, '1.6.2 of the WPForms plugin', 'size_format()' );

		return size_format( $bytes );
	}
}
