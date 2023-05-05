<?php
namespace W3TC;

class UserExperience_LazyLoad_Plugin {
	private $config;
	private $posts_by_url = array();


	public function __construct() {
		$this->config = Dispatcher::config();
	}



	public function run() {
		Util_Bus::add_ob_callback( 'lazyload', array( $this, 'ob_callback' ) );
		$this->metaslider_hooks();

		if ( $this->config->get_boolean( 'lazyload.googlemaps.google_maps_easy' ) ) {
			$p = new UserExperience_LazyLoad_GoogleMaps_GoogleMapsEasy();

			add_filter( 'w3tc_lazyload_mutator_before',
				array( $p, 'w3tc_lazyload_mutator_before' ) );
		}
		if ( $this->config->get_boolean( 'lazyload.googlemaps.wp_google_maps' ) ) {
			add_filter( 'w3tc_lazyload_mutator_before', array(
				new UserExperience_LazyLoad_GoogleMaps_WPGoogleMaps(),
				'w3tc_lazyload_mutator_before'
			) );
		}
		if ( $this->config->get_boolean( 'lazyload.googlemaps.wp_google_map_plugin' ) ) {
			$p = new UserExperience_LazyLoad_GoogleMaps_WPGoogleMapPlugin();

			add_filter( 'w3tc_lazyload_mutator_before',
				array( $p, 'w3tc_lazyload_mutator_before' ) );
		}

		add_filter( 'wp_get_attachment_url',
			array( $this, 'wp_get_attachment_url' ), 10, 2 );
		add_filter( 'w3tc_footer_comment',
			array( $this, 'w3tc_footer_comment' ) );

	}



	public function ob_callback( $buffer ) {
		if ( $buffer == '' || !\W3TC\Util_Content::is_html_xml( $buffer ) ) {
			return $buffer;
		}

		$can_process = array(
			'enabled' => true,
			'buffer' => $buffer,
			'reason' => null
		);

		$can_process = $this->can_process( $can_process );
		$can_process = apply_filters( 'w3tc_lazyload_can_process', $can_process );

		// set reject reason in comment
		if ( $can_process['enabled'] ) {
			$reject_reason = '';
		} else {
			$reject_reason = empty( $can_process['reason'] ) ?
				' (not specified)' : ' (' . $can_process['reason'] . ')';
		}

		$buffer = str_replace( '{w3tc_lazyload_reject_reason}',
			$reject_reason, $buffer );

		// processing
		if ( !$can_process['enabled'] ) {
			return $buffer;
		}

		$mutator = new UserExperience_LazyLoad_Mutator( $this->config, $this->posts_by_url );
		$buffer = $mutator->run( $buffer );

		// embed lazyload script
		if ( $mutator->content_modified() ) {
			$buffer = apply_filters( 'w3tc_lazyload_embed_script', $buffer );

			$is_embed_script = apply_filters( 'w3tc_lazyload_is_embed_script', true );
			if ( $is_embed_script ) {
				$buffer = $this->embed_script( $buffer );
			}
		}

		return $buffer;
	}



	private function can_process( $can_process ) {
		if ( defined( 'WP_ADMIN' ) ) {
			$can_process['enabled'] = false;
			$can_process['reason'] = 'WP_ADMIN';

			return $can_process;
		}

		if ( defined( 'SHORTINIT' ) && SHORTINIT ) {
			$can_process['enabled'] = false;
			$can_process['reason'] = 'SHORTINIT';

			return $can_process;
		}

		if ( function_exists( 'is_feed' ) && is_feed() ) {
			$can_process['enabled'] = false;
			$can_process['reason'] = 'feed';

			return $can_process;
		}

		return $can_process;
	}



	public function w3tc_footer_comment( $strings ) {
		$strings[] = __( 'Lazy Loading', 'w3-total-cache' ) . '{w3tc_lazyload_reject_reason}';
		return $strings;
	}



	private function embed_script( $buffer ) {
		$js_url = plugins_url( 'pub/js/lazyload.min.js', W3TC_FILE );
		$method = $this->config->get_string( 'lazyload.embed_method' );

		$fireEvent = 'function(t){var e;try{e=new CustomEvent("w3tc_lazyload_loaded",{detail:{e:t}})}catch(a){(e=document.createEvent("CustomEvent")).initCustomEvent("w3tc_lazyload_loaded",!1,!1,{e:t})}window.dispatchEvent(e)}';

		$thresholds = '';
		$config_threshold = $this->config->get_string( 'lazyload.threshold' );
		if ( !empty( $config_threshold ) ) {
			$thresholds = 'thresholds:' . json_encode( $config_threshold ) . ',';
		}

		$config = '{elements_selector:".lazy",' . $thresholds . 'callback_loaded:' . $fireEvent . '}';

		$on_initialized_javascript = apply_filters( 'w3tc_lazyload_on_initialized_javascript', '' );

		if ( $method == 'async_head' ) {
			$on_initialized_javascript_wrapped = '';
			if ( !empty( $on_initialized_javascript ) ) {
				// LazyLoad::Initialized fired just before making LazyLoad global
				// so next execution cycle have it
				$on_initialized_javascript_wrapped =
					'window.addEventListener("LazyLoad::Initialized", function(){' .
						'setTimeout(function() {' .
							$on_initialized_javascript .
						'}, 1);' .
					'});';
			}

			$embed_script =
				'<style>img.lazy{min-height:1px}</style>' .
				'<link rel="preload" href="' . esc_url( $js_url ) . '" as="script">';

			$buffer = preg_replace( '~<head(\s+[^>]*)*>~Ui',
				'\\0' . $embed_script, $buffer, 1 );

			// load lazyload in footer to make sure DOM is ready at the moment of initialization
			$footer_script =
				'<script>' .
					$on_initialized_javascript_wrapped .
					'window.w3tc_lazyload=1,' .
					'window.lazyLoadOptions=' . $config .
				'</script>' .
				'<script async src="' . esc_url( $js_url ) . '"></script>';
			$buffer = preg_replace( '~</body(\s+[^>]*)*>~Ui',
				$footer_script . '\\0', $buffer, 1 );

		} elseif ( $method == 'inline_footer' ) {
			$footer_script =
				'<style>img.lazy{min-height:1px}</style>' .
				'<script>' .
				file_get_contents( W3TC_DIR . '/pub/js/lazyload.min.js' ) .
				'window.w3tc_lazyload=new LazyLoad(' . $config . ');' .
				$on_initialized_javascript .
				'</script>';
			$buffer = preg_replace( '~</body(\s+[^>]*)*>~Ui',
				$footer_script . '\\0', $buffer, 1 );
		} else {   // 'sync_head'
			$head_script =
				'<style>img.lazy{min-height:1px}</style>' .
				'<script src="' . esc_url( $js_url ) . '"></script>';
			$buffer = preg_replace( '~<head(\s+[^>]*)*>~Ui',
				'\\0' . $head_script, $buffer, 1 );

			$footer_script =
				'<script>' .
					'window.w3tc_lazyload=new LazyLoad(' . $config . ');' .
					$on_initialized_javascript .
				'</script>';
			$buffer = preg_replace( '~</body(\s+[^>]*)*>~Ui',
				$footer_script . '\\0', $buffer, 1 );
		}

		return $buffer;
	}



	public function wp_get_attachment_url( $url, $post_id ) {
		$this->posts_by_url[$url] = $post_id;
		return $url;
	}



	private function metaslider_hooks() {
		add_filter( 'metaslider_nivo_slider_get_html',
			array( $this, 'metaslider_nivo_slider_get_html' ) );
	}



	public function metaslider_nivo_slider_get_html( $content ) {
		// nivo slider use "src" attr of <img> tags to populate
		// own image via JS, i.e. cant be replaced by lazyloading
		$content = preg_replace(
			'~(\s+)(class=)([\"\'])(.*?)([\"\'])~',
			'$1$2$3$4 no-lazy$5', $content
		);

		return $content;
	}
}
