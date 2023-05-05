<?php
namespace W3TC;

class Generic_Faq {
	static public function sections() {
		// name => column where to show
		return array(
			'General' => 'https://api.w3-edge.com/v1/faq/general',
			'Usage' => 'https://api.w3-edge.com/v1/faq/usage',
			'Compatibility' => 'https://api.w3-edge.com/v1/faq/compatibility',
			'Minification' => 'https://api.w3-edge.com/v1/faq/minification',
			'CDN' => 'https://api.w3-edge.com/v1/faq/cdn',
			'Browser Cache' => 'https://api.w3-edge.com/v1/faq/browser-cache',
			'Errors / Debugging' => 'https://api.w3-edge.com/v1/faq/errors-debugging',
			'Requirements' => 'https://api.w3-edge.com/v1/faq/requirements',
			'Developers' => 'https://api.w3-edge.com/v1/faq/developers',
			'Extensions' => 'https://api.w3-edge.com/v1/faq/extensions',
			'Installation' => 'https://api.w3-edge.com/v1/faq/installation'
		);
	}

	/**
	 * Returns list of questions for section
	 */
	static public function parse( $section ) {
		$faq = array();

		$sections = self::sections();
		if ( !isset( $sections[ $section ] ) ) {
			return null;
		}

		$url = $sections[ $section ];


		$response = wp_remote_get( $url );
		if ( is_wp_error( $response ) ) {
			return null;
		}

		$html = $response['body'];
		$questions = array();

		$m = array();
		preg_match_all( '~<h1>\s*<a[^>]+href="(#[^"]+)[^>]+>.*?</a>([^<]+)</h1>~mi',
			$html, $m );
		if ( is_array( $m ) && count( $m ) > 1 ) {
			for ( $n = 0; $n < count( $m[1] ); $n++ ) {
				$questions[] = array('q' => $m[2][$n], 'a' => $url . $m[1][$n] );
			}
		}

		$m = array();
		preg_match_all( '~<li>\s*<a[^>]+href="([^"]+)[^>]+>(.*?)</a>\s*[.]s*</li>~mi',
			$html, $m );
		if ( is_array( $m ) && count( $m ) > 1 ) {
			for ( $n = 0; $n < count( $m[1] ); $n++ ) {
				$questions[] = array('q' => $m[2][$n], 'a' => $m[1][$n] );
			}
		}

		return $questions;
	}
}
