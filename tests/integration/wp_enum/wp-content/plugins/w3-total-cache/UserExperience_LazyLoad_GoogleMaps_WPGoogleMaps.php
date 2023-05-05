<?php
namespace W3TC;

class UserExperience_LazyLoad_GoogleMaps_WPGoogleMaps {
	private $preload_url = '';



	public function w3tc_lazyload_mutator_before( $data ) {
		$buffer = $data['buffer'];
		$buffer = preg_replace_callback(
			'~(<script\s[^>]+>)~i',
			array( $this, 'tag_script' ), $buffer
		);

		if ( !empty( $this->preload_url ) ) {
			$preload_html = '<link rel="preload" href="' . esc_url( $this->preload_url ) . '" as="script">';

			$buffer = preg_replace( '~<head(\s+[^>]*)*>~Ui',
				'\\0' . $preload_html, $buffer, 1 );

			add_filter( 'w3tc_lazyload_on_initialized_javascript', array(
				$this, 'w3tc_lazyload_on_initialized_javascript' ) );
		}

		$data['buffer'] = $buffer;
		$data['modified'] |= !empty( $this->preload_url );

		return $data;
	}



	public function tag_script( $m ) {
		$script_tag = $m[0];
		if ( !preg_match( '~<script\s+[^<>]*src=["\']?([^"\'> ]+)["\'> ]~is',
				$script_tag, $match ) ) {
			return $script_tag;
		}

		$script_src = $match[1];
		$script_src = Util_Environment::url_relative_to_full( $script_src );

		if ( !$this->starts_with( $script_src, WP_PLUGIN_URL . '/wp-google-maps/js/wpgmaps.js' ) ) {
			return $script_tag;
		}

		$this->preload_url = $script_src;
		return '';
	}



	private function starts_with( $v, $prefix ) {
		return substr( $v, 0, strlen( $prefix ) ) == $prefix;
	}



	public function w3tc_lazyload_on_initialized_javascript() {
		return 'window.w3tc_lazyLazy_googlemaps_wpmaps = new LazyLoad({' .
			'elements_selector: "#wpgmza_map",'.
			'callback_enter: function(e){' .

				// w3tc_load_js function
				'function w3tc_load_js(t,n){"use strict";var o=document.getElementsByTagName("script")[0],r=document.createElement("script");return r.src=t,r.async=!0,o.parentNode.insertBefore(r,o),n&&"function"==typeof n&&(r.onload=n),r};' .

				// hack to allow initialize-on-load script pass
				'MYMAP = {init: function() {},placeMarkers: function() {}};' .

				'w3tc_load_js("' . esc_url( $this->preload_url ) . '", function() {InitMap()});' .
			'}});';
	}
}
