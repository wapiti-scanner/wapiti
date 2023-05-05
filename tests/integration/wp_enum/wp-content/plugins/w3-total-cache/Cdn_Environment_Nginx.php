<?php
namespace W3TC;

/**
 * CDN rules generation for Nginx
 */
class Cdn_Environment_Nginx {
	private $c;



	public function __construct( $config ) {
		$this->c = $config;
	}



	public function generate( $cdnftp ) {
		$rules = '';
		$rule = $this->generate_canonical( $cdnftp );
		if ( !empty( $rule ) ) {
			$rules = $rule . "\n";
		}

		if ( $this->c->get_boolean( 'cdn.cors_header') ) {
			$rules_a = Dispatcher::nginx_rules_for_browsercache_section(
				$this->c, 'other', true );
			$rules_a[] = 'add_header Access-Control-Allow-Origin "*";';

			$rules .=
			"location ~ \\.(ttf|ttc|otf|eot|woff|woff2|font.css)\$ {\n" .
			'    ' . implode( "\n    ", $rules_a ) . "\n" .
			"}\n";
		}

		if ( strlen( $rules ) > 0 ) {
			$rules =
				W3TC_MARKER_BEGIN_CDN . "\n" .
				$rules .
				W3TC_MARKER_END_CDN . "\n";
		}

		return $rules;
	}



	public function generate_canonical( $cdnftp = false ) {
		if ( !$this->c->get_boolean( 'cdn.canonical_header' ) ) {
			return null;
		}

		$home = ( $cdnftp ? Util_Environment::home_url_host() : '$host' );

		return 'add_header Link "<$scheme://' .	$home .
			'$request_uri>; rel=\"canonical\"";';
	}



	public function w3tc_browsercache_rules_section_extensions(
			$extensions, $section ) {
		// CDN adds own rules for those extensions
		if ( $this->c->get_boolean( 'cdn.cors_header') ) {
			unset( $extensions['ttf|ttc'] );
			unset( $extensions['otf'] );
			unset( $extensions['eot'] );
			unset( $extensions['woff'] );
			unset( $extensions['woff2'] );
		}

		return $extensions;
	}
}
