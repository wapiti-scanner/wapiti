<?php
namespace W3TC;

class Extension_Wpml_Plugin_Admin {
	function run() {
		add_filter( 'w3tc_notes', array( $this, 'w3tc_notes' ) );
	}

	function w3tc_notes( $notes ) {
		$config = Dispatcher::config();
		$settings = get_option( 'icl_sitepress_settings' );

		if ( $config->get_boolean( 'pgcache.enabled' ) &&
			$config->get_string( 'pgcache.engine' ) == 'file_generic' &&
			isset( $settings[ 'language_negotiation_type' ] ) &&
			$settings[ 'language_negotiation_type' ] == 3 ) {

			$state = Dispatcher::config_state();

			if ( !$state->get_boolean( 'wpml.hide_note_language_negotiation_type' ) ) {
				$notes[] = sprintf(
					__( 'W3 Total Cache\'s Page caching cannot work effectively when WPML Language URL formatis "Language name added as a parameter" used. Please consider another URL format. Visit the WPML -&gt; Languages settings. %s' ,
						'w3-total-cache' ),
					Util_Ui::button_hide_note2( array(
							'w3tc_default_config_state' => 'y',
							'key' => 'wpml.hide_note_language_negotiation_type',
							'value' => 'true' ) ) );
			}

		}

		return $notes;
	}

	static public function w3tc_extensions( $extensions, $config ) {
		$base_plugin_active = self::base_plugin_active();
		$enabled = $base_plugin_active;
		$disabled_message = '';

		$requirements = array();
		if ( !$base_plugin_active )
			$requirements[] = 'Ensure "WPML" plugin compatibility, which is not currently active.';
		if ( empty( $requirements ) && !Util_Environment::is_w3tc_pro( $config ) ) {
			$enabled = false;
		}

		$extensions['wpml'] = array(
			'name' => 'WPML',
			'author' => 'W3 EDGE',
			'description' => __( 'Improves page caching interoperability with WPML.',
				'w3-total-cache' ),
			'author_uri' => 'https://www.w3-edge.com/',
			'extension_uri' => 'https://www.w3-edge.com/',
			'extension_id' => 'wpml',
			'pro_feature' => true,
			'pro_excerpt' => __( 'Improve the caching performance of websites localized by WPML.', 'w3-total-cache'),
			'pro_description' => array(
				__( 'Localization is a type of personalization that makes websites more difficult to scale. This extension reduces the response time of websites localized by WPML.', 'w3-total-cache')
			),
			'settings_exists' => false,
			'version' => '0.1',
			'enabled' => $enabled,
			'disabled_message' => $disabled_message,
			'requirements' => implode( ', ', $requirements ),
			'path' => 'w3-total-cache/Extension_Wpml_Plugin.php'
		);



		return $extensions;
	}

	static public function base_plugin_active() {
		return defined( 'ICL_SITEPRESS_VERSION' );
	}

	/**
	 * called from outside, since can show notice even when extension is not active
	 */
	static public function w3tc_extensions_hooks( $hooks ) {
		if ( !self::show_notice() )
			return $hooks;

		if ( !isset( $hooks['filters']['w3tc_notes'] ) )
			$hooks['filters']['w3tc_notes'] = array();

		$hooks['filters']['w3tc_notes'][] = 'w3tc_notes_wpml';
		return $hooks;
	}

	static private function show_notice() {
		$config = Dispatcher::config();
		if ( $config->is_extension_active( 'wpml' ) )
			return false;

		if ( !self::base_plugin_active() )
			return false;

		$state = Dispatcher::config_state();
		if ( $state->get_boolean( 'wpml.hide_note_suggest_activation' ) )
			return false;

		return true;
	}

	static public function w3tc_notes_wpml( $notes ) {
		if ( !self::show_notice() )
			return $notes;

		$extension_id = 'wpml';

		$config = Dispatcher::config();
		if ( !Util_Environment::is_w3tc_pro( $config ) )
			$activate_text = 'Available after <a href="#" class="button-buy-plugin" data-src="wpml_requirements3">upgrade</a>. ';
		else {
			$activate_text = sprintf( '<a class="button" href="%s">Click here</a> to try it. ',
				Util_Ui::url( array( 'w3tc_extensions_activate' => $extension_id ) ) );
		}

		$notes[$extension_id] = sprintf(
			__( 'Activating the <a href="%s">WPML</a> extension for W3 Total Cache may be helpful for your site. %s%s',
				'w3-total-cache' ),
			Util_Ui::admin_url( 'admin.php?page=w3tc_extensions#' . $extension_id ),
			$activate_text,
			Util_Ui::button_link(
				__( 'Hide this message', 'w3-total-cache' ),
				Util_Ui::url( array(
						'w3tc_default_config_state' => 'y',
						'key' => 'wpml.hide_note_suggest_activation',
						'value' => 'true' ) ) ) );

		return $notes;
	}
}
