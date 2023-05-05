<?php
namespace W3TC;



class Cdn_Page extends Base_Page_Settings {
	/**
	 * Current page
	 *
	 * @var string
	 */
	protected $_page = 'w3tc_cdn';

	/**
	 * CDN tab
	 *
	 * @return void
	 */
	function view() {
		$config = Dispatcher::config();
		$cdn_engine = $config->get_string( 'cdn.engine' );

		$cdn_enabled = $config->get_boolean( 'cdn.enabled' );
		$cdn_mirror = Cdn_Util::is_engine_mirror( $cdn_engine );
		$cdn_mirror_purge_all = Cdn_Util::can_purge_all( $cdn_engine );
		$cdn_common = Dispatcher::component( 'Cdn_Core' );

		$cdn = $cdn_common->get_cdn();
		$cdn_supports_header = $cdn->headers_support() == W3TC_CDN_HEADER_MIRRORING;
		$minify_enabled = (
			$config->get_boolean( 'minify.enabled' ) &&
			Util_Rule::can_check_rules() &&
			$config->get_boolean( 'minify.rewrite' ) &&
			( !$config->get_boolean( 'minify.auto' ) ||
				Cdn_Util::is_engine_mirror( $config->get_string( 'cdn.engine' ) ) ) );

		$cookie_domain = $this->get_cookie_domain();
		$set_cookie_domain = $this->is_cookie_domain_enabled();

		// Required for Update Media Query String button
		$browsercache_enabled = $config->get_boolean( 'browsercache.enabled' );
		$browsercache_update_media_qs = ( $config->get_boolean( 'browsercache.cssjs.replace' ) || $config->get_boolean( 'browsercache.other.replace' ) );
		include W3TC_INC_DIR . '/options/cdn.php';
	}

	/**
	 * Returns cookie domain
	 *
	 * @return string
	 */
	function get_cookie_domain() {
		$site_url = get_option( 'siteurl' );
		$parse_url = @parse_url( $site_url );

		if ( $parse_url && !empty( $parse_url['host'] ) ) {
			return $parse_url['host'];
		}

		return isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '';
	}

	/**
	 * Checks if COOKIE_DOMAIN is enabled
	 *
	 * @return bool
	 */
	function is_cookie_domain_enabled() {
		$cookie_domain = $this->get_cookie_domain();

		return defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN == $cookie_domain;
	}
}
