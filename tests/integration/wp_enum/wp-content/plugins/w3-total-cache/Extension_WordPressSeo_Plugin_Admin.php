<?php
namespace W3TC;

class Extension_WordPressSeo_Plugin_Admin {
	function run() {
		add_filter( 'w3tc_extension_plugin_links_wordpress-seo', array( $this, 'remove_settings' ) );
		add_action( 'w3tc_activate_extension_wordpress-seo', array( $this, 'activate' ) );
		add_action( 'w3tc_deactivate_extension_wordpress-seo', array( $this, 'deactivate' ) );
	}

	/**
	 *
	 *
	 * @param unknown $links
	 * @return mixed
	 */
	public function remove_settings( $links ) {
		array_pop( $links );
		return $links;
	}

	/**
	 *
	 *
	 * @param unknown $extensions
	 * @param Config  $config
	 * @return mixed
	 */
	static public function w3tc_extensions( $extensions, $config ) {
		$message = array();
		if ( !self::criteria_match() )
			$message[] = 'Optimizes "Yoast SEO" plugin, which is not active';

		$extensions['wordpress-seo'] = array (
			'name' => 'Yoast SEO',
			'author' => 'W3 EDGE',
			'description' => __( 'Configures W3 Total Cache to comply with Yoast SEO requirements automatically.', 'w3-total-cache' ),

			'author_uri' => 'https://www.w3-edge.com/',
			'extension_uri' => 'https://www.w3-edge.com/',
			'extension_id' => 'wordpress-seo',
			'settings_exists' => true,
			'version' => '0.1',
			'enabled' => self::criteria_match(),
			'requirements' => implode( ', ', $message ),
			'path' => 'w3-total-cache/Extension_WordPressSeo_Plugin.php'
		);

		return $extensions;
	}

	/**
	 * called from outside, since can show notice even when extension is not active
	 */
	static public function w3tc_extensions_hooks( $hooks ) {
		if ( !self::show_notice() )
			return $hooks;

		if ( !isset( $hooks['filters']['w3tc_notes'] ) )
			$hooks['filters']['w3tc_notes'] = array();

		$hooks['filters']['w3tc_notes'][] = 'w3tc_notes_wordpress_seo';
		return $hooks;
	}

	static private function show_notice() {
		$config = Dispatcher::config();
		if ( $config->is_extension_active( 'wordpress-seo' ) )
			return false;

		if ( !self::criteria_match() )
			return false;

		$state = Dispatcher::config_state();
		if ( $state->get_boolean( 'wordpress_seo.hide_note_suggest_activation' ) )
			return false;

		return true;
	}

	static public function w3tc_notes_wordpress_seo( $notes ) {
		if ( !self::show_notice() )
			return $notes;

		$extension_id = 'wordpress-seo';

		$notes[$extension_id] = sprintf(
			__(
				'Activating the <a href="%s">Yoast SEO</a> extension for W3 Total Cache may be helpful for your site. <a class="button" href="%s">Click here</a> to try it. %s',
				'w3-total-cache'
			),
			Util_Ui::admin_url( 'admin.php?page=w3tc_extensions#' . $extension_id ),
			Util_Ui::url( array( 'w3tc_extensions_activate' => $extension_id ) ),
			Util_Ui::button_link(
				__( 'Hide this message', 'w3-total-cache' ),
				Util_Ui::url(
					array(
						'w3tc_default_config_state' => 'y',
						'key'                       => 'wordpress_seo.hide_note_suggest_activation',
						'value'                     => 'true'
					)
				)
			)
		);

		return $notes;
	}

	static private function criteria_match() {
		return defined( 'WPSEO_VERSION' );
	}

	public function activate() {
		try {
			$config = Dispatcher::config();
			$config->set( 'pgcache.prime.enabled', true );
			$config->set( 'pgcache.prime.sitemap', '/sitemap_index.xml' );
			$config->save();
		} catch ( \Exception $ex ) {}
	}

	public function deactivate() {
		try {
			$config = Dispatcher::config();
			$config->set( 'pgcache.prime.enabled', false );
			$config->save();
		} catch ( \Exception $ex ) {}
	}
}
