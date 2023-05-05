<?php
/**
 * Stats Initial State
 *
 * @package automattic/jetpack-stats-admin
 */

namespace Automattic\Jetpack\Stats_Admin;

use Automattic\Jetpack\Modules;
use Jetpack_Options;

/**
 * Class Odyssey_Config_Data
 *
 * @package automattic/jetpack-stats-admin
 */
class Odyssey_Config_Data {

	/**
	 * Set configData to window.configData.
	 *
	 * @param string $config_variable_name The config variable name.
	 * @param array  $config_data The config data.
	 */
	public function get_js_config_data( $config_variable_name = 'configData', $config_data = null ) {
		return "window.{$config_variable_name} = " . wp_json_encode(
			$config_data === null ? $this->get_data() : $config_data
		) . ';';
	}

	/**
	 * Return the config for the app.
	 */
	public function get_data() {
		$blog_id      = Jetpack_Options::get_option( 'id' );
		$empty_object = json_decode( '{}' );
		return array(
			'admin_page_base'                => $this->get_admin_path(),
			'api_root'                       => esc_url_raw( rest_url() ),
			'blog_id'                        => Jetpack_Options::get_option( 'id' ),
			'enable_all_sections'            => false,
			'env_id'                         => 'production',
			'google_analytics_key'           => 'UA-10673494-15',
			'google_maps_and_places_api_key' => '',
			'hostname'                       => wp_parse_url( get_site_url(), PHP_URL_HOST ),
			'i18n_default_locale_slug'       => 'en',
			'i18n_locale_slug'               => $this->get_site_locale(),
			'mc_analytics_enabled'           => false,
			'meta'                           => array(),
			'nonce'                          => wp_create_nonce( 'wp_rest' ),
			'site_name'                      => \get_bloginfo( 'name' ),
			'sections'                       => array(),
			// Features are inlined @see https://github.com/Automattic/wp-calypso/pull/70122
			'features'                       => array(),
			// Intended for apps that do not use redux.
			'gmt_offset'                     => $this->get_gmt_offset(),
			// TODO: check whether this works with Pressable.
			'odyssey_stats_base_url'         => admin_url( 'admin.php?page=stats' ),
			'intial_state'                   => array(
				'currentUser' => array(
					'id'           => 1000,
					'user'         => array(
						'ID'       => 1000,
						'username' => 'no-user',
					),
					'capabilities' => array(
						"$blog_id" => $this->get_current_user_capabilities(),
					),
				),
				'sites'       => array(
					'items'    => array(
						"$blog_id" => array(
							'ID'            => $blog_id,
							'URL'           => site_url(),
							'jetpack'       => true,
							'visible'       => true,
							'capabilities'  => $empty_object,
							'products'      => array(),
							'plan'          => $empty_object, // we need this empty object, otherwise the front end would crash on insight page.
							'options'       => array(
								'wordads'    => ( new Modules() )->is_active( 'wordads' ),
								'admin_url'  => admin_url(),
								'gmt_offset' => $this->get_gmt_offset(),
							),
							'stats_notices' => ( new Notices() )->get_notices_to_show(),
						),
					),
					'features' => array( "$blog_id" => array( 'data' => $this->get_plan_features() ) ),
				),
			),
		);
	}

	/**
	 * Get the current site GMT Offset.
	 *
	 * @return float The current site GMT Offset by hours.
	 */
	protected function get_gmt_offset() {
		return (float) get_option( 'gmt_offset' );
	}

	/**
	 * Page base for the Calypso admin page.
	 */
	protected function get_admin_path() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! isset( $_SERVER['PHP_SELF'] ) || ! isset( $_SERVER['QUERY_STRING'] ) ) {
			$parsed = wp_parse_url( admin_url( 'admin.php?page=stats' ) );
			return $parsed['path'] . '?' . $parsed['query'];
		}
		// We do this because page.js requires the exactly page base to be set otherwise it will not work properly.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		return wp_unslash( $_SERVER['PHP_SELF'] ) . '?' . wp_unslash( $_SERVER['QUERY_STRING'] );
	}

	/**
	 * Get locale acceptable by Calypso.
	 */
	protected function get_site_locale() {
		/**
		 * In WP, locales are formatted as LANGUAGE_REGION, for example `en`, `en_US`, `es_AR`,
		 * but Calypso expects language-region, e.g. `en-us`, `en`,  `es-ar`. So we need to convert
		 * them to lower case and replace the underscore with a dash.
		 */
		$locale = strtolower( get_locale() );
		$locale = str_replace( '_', '-', $locale );

		return $locale;
	}

	/**
	 * Get the features of the current plan.
	 */
	protected function get_plan_features() {
		if ( ! class_exists( 'Jetpack_Plan' ) ) {
			return array();
		}
		$plan = \Jetpack_Plan::get();
		if ( empty( $plan['features'] ) ) {
			return array();
		}
		return $plan['features'];
	}

	/**
	 * Get the capabilities of the current user.
	 *
	 * @return array An array of capabilities.
	 */
	protected function get_current_user_capabilities() {
		$user = wp_get_current_user();
		if ( ! $user || is_wp_error( $user ) ) {
			return array();
		}
		return $user->allcaps;
	}
}
