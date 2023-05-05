<?php
namespace W3TC;

class Extension_WordPressSeo_Plugin {
	private $_config;

	function __construct() {
		$this->_config = Dispatcher::config();
	}

	public function run() {
		if ( $this->_config->get_boolean( 'cdn.enabled' ) ) {
			add_filter( 'wpseo_xml_sitemap_img_src', array(
					$this, 'wpseo_cdn_filter' ) );
		}
	}

	/**
	 * Hook into Yoast SEO sitemap image filter.
	 *
	 * @param unknown $uri
	 * @return string
	 */
	public function wpseo_cdn_filter( $uri ) {
		$common = Dispatcher::component( 'Cdn_Core' );
		$cdn = $common->get_cdn();
		$parsed = parse_url( $uri );
		$path = $parsed['path'];
		$remote_path = $common->uri_to_cdn_uri( $path );
		$new_url = $cdn->format_url( $remote_path );

		return  $new_url;
	}
}



$p = new Extension_WordPressSeo_Plugin();
$p->run();

if ( is_admin() ) {
	$p = new Extension_WordPressSeo_Plugin_Admin();
	$p->run();
}
