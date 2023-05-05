<?php
namespace W3TC;

/**
 * Minify rules generation for LiteSpeed
 */
class Minify_Environment_LiteSpeed {
	private $c;



	public function __construct( $config ) {
		$this->c = $config;
	}



	// force rewrites to work in order to get minify a chance to generate content
	public function w3tc_browsercache_rules_section( $section_rules, $section ) {
		if ( $section == 'cssjs' ) {
			$section_rules['rewrite'] = true;
		}

		return $section_rules;
	}
}
