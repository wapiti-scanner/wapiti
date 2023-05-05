<?php
namespace W3TC;

/**
 * CDN rules generation for LiteSpeed
 */
class Cdn_Environment_LiteSpeed {
	private $c;



	public function __construct( $config ) {
		$this->c = $config;
	}



	public function generate( $cdnftp ) {
		$section_rules = [
			'other' => [],
			'add_header' => []
		];

		if ( $this->c->get_boolean( 'cdn.cors_header') ) {
			$section_rules['add_header'][] = 'set Access-Control-Allow-Origin "*"';
		}

		$canonical_header = $this->generate_canonical( $cdnftp );
		if ( !empty( $canonical_header ) ) {
			$section_rules['add_header'][] = $canonical_header;
		}

		if ( empty( $section_rules['add_header'] ) ) {
			return '';
		}

		$section_rules = apply_filters( 'w3tc_cdn_rules_section', $section_rules, $this->c );

		$context_rules[] = "    extraHeaders <<<END_extraHeaders";
		foreach ( $section_rules['add_header'] as $line ) {
			$context_rules[] = '        ' . $line;
		}
		$context_rules[] = "    END_extraHeaders";

		$rules = [];
		$rules[] = 'context exp:^.*(ttf|ttc|otf|eot|woff|woff2|font.css)$ {';
		$rules[] = '    location $DOC_ROOT/$0';
		$rules[] = '    allowBrowse 1';
		$rules[] = implode( "\n", $context_rules );
		$rules[] = '}';

		return
			W3TC_MARKER_BEGIN_CDN . "\n" .
			implode( "\n", $rules ) . "\n" .
			W3TC_MARKER_END_CDN . "\n";
	}



	public function generate_canonical( $cdnftp = false ) {
		if ( !$this->c->get_boolean( 'cdn.canonical_header' ) ) {
			return null;
		}

		$home_url  = get_home_url();
		$parse_url = @parse_url( $home_url ); // phpcs:ignore
		if ( !isset( $parse_url['host'] ) ) {
			return null;
		}

		return "set Link '<" . $parse_url['scheme'] . '://' .	$parse_url['host'] .
			'%{REQUEST_URI}e>; rel="canonical"' . "'";
/*
			$rules .= "      RewriteRule .* - [E=CANONICAL:https://$host%{REQUEST_URI},NE]\n";
			$rules .= "   </IfModule>\n";
			$rules .= "   <IfModule mod_headers.c>\n";
			$rules .= '      Header set Link "<%{CANONICAL}e>; rel=\"canonical\""' . "\n";

			return 'set Link "<%{CANONICAL}e>; rel=\"canonical\""' . "\n";*/
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



	// add canonical header to all browsercache sections, since its needed for
	// assets
	public function w3tc_browsercache_rules_section( $section_rules, $section ) {
		$canonical_header = $this->generate_canonical();
		if ( !empty( $canonical_header ) ) {
			$section_rules['add_header'][] = $canonical_header;
		}

		return $section_rules;
	}
}
