<?php
namespace W3TC;

class UserExperience_LazyLoad_GoogleMaps_WPGoogleMapPlugin {
	public function w3tc_lazyload_mutator_before( $data ) {
		$buffer = $data['buffer'];
		if (strpos( $buffer, '<script>jQuery(document).ready(function($) {var map' ) === false ) {
			return $data;
		}

		$buffer = str_replace(
			'<script>jQuery(document).ready(function($) {var map',
			'<script>window.w3tc_wpgmp_load = (function($) {var map',
			$buffer
		);

		add_filter( 'w3tc_lazyload_on_initialized_javascript', array(
			$this, 'w3tc_lazyload_on_initialized_javascript' ) );

		$data['buffer'] = $buffer;
		$data['modified'] = true;

		return $data;
	}



	public function w3tc_lazyload_on_initialized_javascript() {
		return 'window.w3tc_lazyLazy_googlemaps_wpmapplugin = new LazyLoad({' .
			'elements_selector: ".wpgmp_map_container",'.
			'callback_enter: function(e){' .
				'window.w3tc_wpgmp_load(jQuery)'.
			'}});';
	}
}
