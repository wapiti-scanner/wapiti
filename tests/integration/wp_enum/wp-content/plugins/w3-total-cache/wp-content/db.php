<?php
/**
 * W3 Total Cache Database module
 */

if ( ! defined( 'ABSPATH' ) ) {
	die();
}

if ( ! defined( 'W3TC_DIR' ) ) {
	define( 'W3TC_DIR', ( defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : WP_CONTENT_DIR . '/plugins' ) . '/w3-total-cache' );
}

/**
 * Abort W3TC loading if WordPress is upgrading
 */
if ( ! @is_dir( W3TC_DIR ) || ! file_exists( W3TC_DIR . '/w3-total-cache-api.php' ) ) {
	if ( ! defined( 'WP_ADMIN' ) ) {
		global $wp_version;

		// lets don't show error on front end.
		if ( version_compare( $wp_version, '6.1-beta1', '>=' ) ) {
			require_once ABSPATH . WPINC . '/class-wpdb.php';
		} else {
			require_once ABSPATH . WPINC . '/wp-db.php';
		}
	} else {
		echo wp_kses(
			sprintf(
				// translators: 1 opening HTML strong tag, 2 closing HTML strong tag, 3 opening HTML strong tag,
				// translators: 4 file path, 5 closing HTML strong tag, 6 HTML line break.
				__(
					'%1$sW3 Total Cache Error:%2$s some files appear to be missing or out of place. Please re-install plugin or remove %3$s%4$s%5$s. %6$s',
					'w3-total-cache'
				),
				'<strong>',
				'</strong>',
				'<strong>',
				'</strong>',
				__FILE__,
				'<br />'
			),
			array(
				'strong' => array(),
				'br'     => array(),
			)
		);
	}
} else {
	require_once W3TC_DIR . '/w3-total-cache-api.php';

	// no caching during activation.
	$is_installing = ( defined( 'WP_INSTALLING' ) && WP_INSTALLING );

	$config = \W3TC\Dispatcher::config();
	if ( ( ! $is_installing && $config->get_boolean( 'dbcache.enabled' ) ) || \W3TC\Util_Environment::is_dbcluster() ) {
		if ( defined( 'DB_TYPE' ) ) {
			$db_driver_path = sprintf( '%s/Db/%s.php', W3TC_LIB_DIR, DB_TYPE );

			if ( file_exists( $db_driver_path ) ) {
				require_once $db_driver_path;
			} else {
				die(
					wp_kses(
						sprintf(
							// translators: 1 opening HTML strong tag, 2 closing HTML strong tag, 3 database driver file path.
							__(
								'%1$sW3 Total Cache Error:%2$s database driver doesn\'t exist: %3$s.',
								'w3-total-cache'
							),
							'<strong>',
							'</strong>',
							esc_html( $db_driver_path )
						),
						array( 'strong' => array() )
					)
				);
			}
		}

		$GLOBALS['wpdb'] = \W3TC\DbCache_Wpdb::instance();
	}
}
