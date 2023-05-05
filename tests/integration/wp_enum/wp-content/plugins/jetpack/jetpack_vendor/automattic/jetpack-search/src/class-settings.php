<?php
/**
 * Jetpack Search Overlay Settings
 *
 * @package automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search;

// Exit if file is accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class to initialize search settings on the site.
 *
 * 1. Settings are synced to WPCOM according to `Automattic\Jetpack\Sync\Modules\Search::$options_to_sync`.
 * 2. All synced options must also be explicitly whitelisted and sanitized on WPCOM; see `PCYsg-sBM-p2`.
 */
class Settings {

	/**
	 * Class initialization.
	 */
	public function __construct() {
		add_action( 'admin_init', array( $this, 'settings_register' ) );
		add_action( 'rest_api_init', array( $this, 'settings_register' ) );
	}

	/**
	 * Register requisite settings.
	 *
	 * @since 9.x.x
	 */
	public function settings_register() {
		// NOTE: This contains significant code overlap with class-jetpack-search-customize.
		$setting_prefix = Options::OPTION_PREFIX;
		$settings       = array(
			array( $setting_prefix . 'color_theme', 'string', 'light' ),
			array( $setting_prefix . 'result_format', 'string', 'minimal' ),
			array( $setting_prefix . 'default_sort', 'string', 'relevance' ),
			array( $setting_prefix . 'overlay_trigger', 'string', Options::DEFAULT_OVERLAY_TRIGGER ),
			array( $setting_prefix . 'excluded_post_types', 'string', '' ),
			array( $setting_prefix . 'highlight_color', 'string', '#FFC' ),
			array( $setting_prefix . 'enable_sort', 'boolean', true ),
			array( $setting_prefix . 'inf_scroll', 'boolean', true ),
			array( $setting_prefix . 'show_post_date', 'boolean', true ),
			array( $setting_prefix . 'show_powered_by', 'boolean', true ),
		);
		foreach ( $settings as $value ) {
			register_setting(
				'options',
				$value[0],
				array(
					'default'      => $value[2],
					'show_in_rest' => true,
					'type'         => $value[1],
				)
			);
		}
	}
}
