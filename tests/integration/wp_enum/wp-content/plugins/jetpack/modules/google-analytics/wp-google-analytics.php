<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/*
	Copyright 2006 Aaron D. Campbell (email : wp_plugins@xavisys.com)

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once plugin_basename( 'classes/wp-google-analytics-utils.php' );
require_once plugin_basename( 'classes/wp-google-analytics-options.php' );
require_once plugin_basename( 'classes/wp-google-analytics-legacy.php' );
require_once plugin_basename( 'classes/wp-google-analytics-universal.php' );
require_once plugin_basename( 'classes/class-jetpack-google-amp-analytics.php' );

/**
 * Jetpack_Google_Analytics is the class that handles ALL of the plugin functionality.
 * It helps us avoid name collisions
 * https://codex.wordpress.org/Writing_a_Plugin#Avoiding_Function_Name_Collisions
 */
class Jetpack_Google_Analytics {

	/**
	 * Jetpack_Google_Analytics singleton instance.
	 *
	 * @var Jetpack_Google_Analytics
	 */
	public static $instance = false;

	/**
	 * Property to hold concrete analytics implementation that does the work (universal or legacy).
	 *
	 * @var Static
	 */
	public static $analytics = false;

	/**
	 * This is our constructor, which is private to force the use of get_instance()
	 *
	 * @return void
	 */
	private function __construct() {
		// At this time, we only leverage universal analytics when enhanced ecommerce is selected and WooCommerce is active.
		// Otherwise, don't bother emitting the tracking ID or fetching analytics.js
		if ( class_exists( 'WooCommerce' ) && Jetpack_Google_Analytics_Options::enhanced_ecommerce_tracking_is_enabled() ) {
			self::$analytics = new Jetpack_Google_Analytics_Universal();
			new Jetpack_Google_AMP_Analytics();
		} else {
			self::$analytics = new Jetpack_Google_Analytics_Legacy();
		}
	}

	/**
	 * Function to instantiate our class and make it a singleton
	 */
	public static function get_instance() {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Add amp-analytics tags.
	 *
	 * @param array $analytics_entries An associative array of the analytics entries.
	 *
	 * @return array
	 */
	public static function amp_analytics_entries( $analytics_entries ) {
		if ( ! is_array( $analytics_entries ) ) {
			$analytics_entries = array();
		}

		$amp_tracking_codes = static::get_amp_tracking_codes( $analytics_entries );
		$jetpack_account    = Jetpack_Google_Analytics_Options::get_tracking_code();

		// Bypass tracking codes already set on AMP plugin.
		if ( in_array( $jetpack_account, $amp_tracking_codes, true ) ) {
			return $analytics_entries;
		}

		$config_data = wp_json_encode(
			array(
				'vars'     => array(
					'account' => Jetpack_Google_Analytics_Options::get_tracking_code(),
				),
				'triggers' => array(
					'trackPageview' => array(
						'on'      => 'visible',
						'request' => 'pageview',
					),
				),
			)
		);

		// Generate a hash string to uniquely identify this entry.
		$entry_id = substr( md5( 'googleanalytics' . $config_data ), 0, 12 );

		$analytics_entries[ $entry_id ] = array(
			'type'   => 'googleanalytics',
			'config' => $config_data,
		);

		return $analytics_entries;
	}

	/**
	 * Get AMP tracking codes.
	 *
	 * @param array $analytics_entries The codes available for AMP.
	 *
	 * @return array
	 */
	protected static function get_amp_tracking_codes( $analytics_entries ) {
		$entries  = array_column( $analytics_entries, 'config' );
		$accounts = array();

		foreach ( $entries as $entry ) {
			$entry = json_decode( $entry );

			if ( ! empty( $entry->vars->account ) ) {
				$accounts[] = $entry->vars->account;
			}
		}

		return $accounts;
	}
}

global $jetpack_google_analytics;
$jetpack_google_analytics = Jetpack_Google_Analytics::get_instance();
