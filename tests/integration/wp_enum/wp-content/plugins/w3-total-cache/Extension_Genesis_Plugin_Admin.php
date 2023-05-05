<?php
namespace W3TC;
/**
 * W3 GenesisExtension module
 */

class Extension_Genesis_Plugin_Admin {
	function run() {
		add_action( 'w3tc_extension_page_genesis.theme', array(
				'\W3TC\Extension_Genesis_Page',
				'w3tc_extension_page_genesis_theme'
			) );
		add_filter( 'w3tc_errors', array( $this, 'w3tc_errors' ) );
	}



	/**
	 *
	 *
	 * @param unknown $extensions
	 * @param Config  $config
	 * @return mixed
	 */
	static public function w3tc_extensions( $extensions, $config ) {
		$requirements = array();

		if ( !self::is_theme_found() )
			$requirements[] =
				'Optimizes "Genesis Framework" version >= 1.9.0, which is not active';

		if ( !$config->is_extension_active( 'fragmentcache' ) )
			$requirements[] = 'Activate "Fragment Cache" extension first';

		$extensions['genesis.theme'] = array (
			'name' => 'Genesis Framework by StudioPress',
			'author' => 'W3 EDGE',
			'description' => 'Provides 30-60% improvement in page generation time for the Genesis Framework by Copyblogger Media.',
			'author_uri' => 'https://www.w3-edge.com/',
			'extension_uri' => 'https://www.w3-edge.com/',
			'extension_id' => 'genesis.theme',
			'pro_feature' => true,
			'pro_excerpt' => __( 'Increase the performance of themes powered by the Genesis Theme Framework by up to 60%.', 'w3-total-cache'),
			'pro_description' => array(),
			'settings_exists' => true,
			'version' => '0.1',
			'enabled' => empty( $requirements ),
			'requirements' => implode( ', ', $requirements ),
			'path' => 'w3-total-cache/Extension_Genesis_Plugin.php'
		);

		return $extensions;
	}



	/**
	 * Show errors in wp-admin
	 */
	function w3tc_errors( $errors ) {
		$c = Dispatcher::config();

		if ( !$c->is_extension_active_frontend( 'fragmentcache' ) ) {
			$errors['genesis_fragmentcache_disabled'] =
				__( 'Please enable <strong>Fragment Cache</strong> module to make sure <strong>Genesis extension</strong> works properly.',
				'w3-total-cache' );
		}

		return $errors;
	}



	static private function is_theme_found() {
		if ( !is_network_admin() )
			return ( defined( 'PARENT_THEME_NAME' ) &&
				PARENT_THEME_NAME == 'Genesis' );

		$themes = Util_Theme::get_themes();
		$theme_found = false;
		foreach ( $themes as $theme ) {
			if ( strtolower( $theme->Template ) == 'genesis' )
				return true;
		}
	}



	/**
	 * called from outside, since can show notice even when extension is not active
	 */
	static public function w3tc_extensions_hooks( $hooks ) {
		if ( !self::show_notice() )
			return $hooks;

		if ( !isset( $hooks['filters']['w3tc_notes'] ) )
			$hooks['filters']['w3tc_notes'] = array();

		$hooks['filters']['w3tc_notes'][] = 'w3tc_notes_genesis_theme';
		return $hooks;
	}

	static private function show_notice() {
		$config = Dispatcher::config();
		if ( $config->is_extension_active( 'genesis.theme' ) )
			return false;

		if ( !self::is_theme_found() )
			return false;

		$state = Dispatcher::config_state();
		if ( $state->get_boolean( 'genesis.theme.hide_note_suggest_activation' ) )
			return false;

		return true;
	}

	static public function w3tc_notes_genesis_theme( $notes ) {
		if ( !self::show_notice() )
			return $notes;

		$extension_id = 'genesis.theme';

		$notes[$extension_id] = sprintf(
			__( 'Activating the <a href="%s">Genesis Theme</a> extension for W3 Total Cache may be helpful for your site. <a href="%s">Click here</a> to try it. %s',
				'w3-total-cache' ),
			Util_Ui::admin_url( 'admin.php?page=w3tc_extensions#' . $extension_id ),
			Util_Ui::url( array( 'w3tc_extensions_activate' => $extension_id ) ),
			Util_Ui::button_link(
				__( 'Hide this message', 'w3-total-cache' ),
				Util_Ui::url( array(
						'w3tc_default_config_state' => 'y',
						'key' => 'genesis.theme.hide_note_suggest_activation',
						'value' => 'true' ) ) ) );

		return $notes;
	}
}
