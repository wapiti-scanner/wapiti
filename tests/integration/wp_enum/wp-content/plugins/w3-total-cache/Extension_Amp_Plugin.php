<?php
namespace W3TC;

class Extension_Amp_Plugin {
	private $is_amp_endpoint = null;



	static public function wp_loaded() {
		add_action( 'w3tc_extension_load', array(
			'\W3TC\Extension_Amp_Plugin',
			'w3tc_extension_load'
		) );
		add_action( 'w3tc_extension_load_admin', array(
			'\W3TC\Extension_Amp_Plugin_Admin',
			'w3tc_extension_load_admin'
		) );
	}



	static public function w3tc_extension_load() {
		$o = new Extension_Amp_Plugin();

		add_filter( 'w3tc_minify_js_enable',
			array( $o, 'w3tc_minify_jscss_enable' ) );
		add_filter( 'w3tc_minify_css_enable',
			array( $o, 'w3tc_minify_jscss_enable' ) );
		add_filter( 'w3tc_lazyload_can_process',
			array( $o, 'w3tc_lazyload_can_process' ) );
		add_filter( 'w3tc_footer_comment',
			array( $o, 'w3tc_footer_comment' ) );
		add_filter( 'w3tc_newrelic_should_disable_auto_rum',
			array( $o, 'w3tc_newrelic_should_disable_auto_rum' ) );
		add_filter( 'pgcache_flush_post_queued_urls',
			array( $o, 'x_flush_post_queued_urls' ) );
		add_filter( 'varnish_flush_post_queued_urls',
			array( $o, 'x_flush_post_queued_urls' ) );
		add_filter( 'w3tc_pagecache_set',
			array( $o, 'w3tc_pagecache_set' ) );
		add_filter( 'w3tc_config_default_values',
			array( $o, 'w3tc_config_default_values' ) );

		// rules generation
		add_filter( 'w3tc_pagecache_rules_apache_accept_qs',
			array( $o, 'w3tc_pagecache_rules_x_accept_qs' ) );
		add_filter( 'w3tc_pagecache_rules_apache_accept_qs_rules',
			array( $o, 'w3tc_pagecache_rules_apache_accept_qs_rules' ), 10, 2 );
		add_filter( 'w3tc_pagecache_rules_apache_uri_prefix',
			array( $o, 'w3tc_pagecache_rules_apache_uri_prefix' ) );

		add_filter( 'w3tc_pagecache_rules_nginx_accept_qs',
			array( $o, 'w3tc_pagecache_rules_x_accept_qs' ) );
		add_filter( 'w3tc_pagecache_rules_nginx_accept_qs_rules',
			array( $o, 'w3tc_pagecache_rules_nginx_accept_qs_rules' ), 10, 2 );
		add_filter( 'w3tc_pagecache_rules_nginx_uri_prefix',
			array( $o, 'w3tc_pagecache_rules_nginx_uri_prefix' ) );
	}



	private function is_amp_endpoint() {
		// support for different plugins defining those own functions
		if ( is_null( $this->is_amp_endpoint ) ) {
			if ( function_exists( 'is_amp_endpoint' ) ) {
				$this->is_amp_endpoint = is_amp_endpoint();
			} elseif ( function_exists( 'ampforwp_is_amp_endpoint' ) ) {
				$this->is_amp_endpoint = ampforwp_is_amp_endpoint();
			} elseif ( function_exists( 'is_better_amp' ) ) {
				$this->is_amp_endpoint = is_better_amp();
			}
		}

		return is_null( $this->is_amp_endpoint ) ? false : $this->is_amp_endpoint;
	}



	public function w3tc_minify_jscss_enable( $enabled ) {
		if ( $this->is_amp_endpoint() ) {
			// amp has own rules for CSS and JS files, don't touch them by default
			return false;
		}

		return $enabled;
	}



	public function w3tc_newrelic_should_disable_auto_rum( $reject_reason ) {
		if ( $this->is_amp_endpoint() ) {
			return 'AMP endpoint';
		}

		return $reject_reason;
	}



	public function w3tc_lazyload_can_process( $can_process ) {
		if ( $this->is_amp_endpoint() ) {
			$can_process['enabled'] = false;
			$can_process['reason'] = 'AMP endpoint';
		}

		return $can_process;
	}



	public function x_flush_post_queued_urls( $queued_urls ) {
		$amp_urls = array();
		$c = Dispatcher::config();
		$url_postfix = $c->get_string( array( 'amp', 'url_postfix' ) );

		if ( $c->get_string( array( 'amp', 'url_type' ) ) == 'querystring' ) {
			foreach ( $queued_urls as $url ) {
				$amp_urls[] = $url . '?' . $url_postfix;
			}
		} else {
			foreach ( $queued_urls as $url ) {
				$amp_urls[] = trailingslashit( $url ) . $url_postfix;
			}
		}

		$queued_urls = array_merge( $queued_urls, $amp_urls );
		return $queued_urls;
	}



	public function w3tc_footer_comment( $strings ) {
		if ( $this->is_amp_endpoint() ) {
			$strings[] = 'AMP page, minification is limited';
		}

		return $strings;
	}



	public function w3tc_pagecache_set( $data ) {
		if ( $this->is_amp_endpoint() ) {
			// workaround to prevent Link headers from parent page
			// to appear in amp page coming from it's .htaccess
			$c = Dispatcher::config();
			if ( $c->getf_boolean( 'minify.css.http2push' ) ||
					$c->getf_boolean( 'minify.js.http2push' ) ) {
				$data['headers'][] = array(
					'n' => 'Link', 'v' => '', 'files_match' => '\\.html[_a-z]*$' );

				$this->w3tc_pagecache_set_header_register_once();
			}
		}

		return $data;
	}



	private function w3tc_pagecache_set_header_register_once() {
		static $registered = false;

		if ( !$registered ) {
			add_filter( 'w3tc_pagecache_set_header',
				array( $this, 'w3tc_pagecache_set_header' ), 20, 2 );
		}
	}



	public function w3tc_pagecache_set_header( $header, $header_original ) {
		if ( $header_original['n'] == 'Link' && empty( $header_original['v'] ) ) {
			// forces removal of Link header for file_generic when its set by
			// parent .htaccess
			return $header_original;
		}

		return $header;
	}



	public function w3tc_config_default_values( $default_values ) {
		$default_values['amp'] = array(
			'url_type' => 'tag',
			'url_postfix' => 'amp'
		);

		return $default_values;
	}



	static public function pagecache_normalize_url_fragments( $url_fragments ) {
		$c = Dispatcher::config();

		if ( $c->get_string( array( 'amp', 'url_type' ) ) == 'querystring' ) {
			if ( !empty( $url_fragments['querystring'] ) ) {
				$qs = $c->get_string( array( 'amp', 'url_postfix' ) );

				$url_qs = substr( $url_fragments['querystring'], 1 );   // cut off "?"

				$regexp = Util_Environment::preg_quote( str_replace( '+', ' ', $qs ) );
				if ( @preg_match( "~^(.*?&|)$regexp(=[^&]*)?(&.*|)$~i", $url_qs, $m ) ) {
					$url_qs = $m[1] . $m[3];
					$url_qs = preg_replace( '~[&]+~', '&', $url_qs );
					$url_qs = trim( $url_qs, '&' );
					$url_qs = empty( $url_qs ) ? '' : '?' . $url_qs;

					$url_fragments['querystring'] = $url_qs;
					$url_fragments['amp_extension'] = 1;
				}
			}
		}

		return $url_fragments;
	}



	static public function pagecache_page_key( $o ) {
		$c = Dispatcher::config();

		if ( isset( $o['url_fragments']['amp_extension'] ) ) {
			$o['key'][1] .= '_amp';

		}

		return $o;
	}



	public function w3tc_pagecache_rules_x_accept_qs( $query_strings ) {
		$c = Dispatcher::config();

		if ( $c->get_string( array( 'amp', 'url_type' ) ) == 'querystring' ) {
			$query_strings[] = $c->get_string( array( 'amp', 'url_postfix' ) );
		}

		return $query_strings;
	}



	public function w3tc_pagecache_rules_apache_accept_qs_rules( $query_rules, $query ) {
		$c = Dispatcher::config();

		if ( $c->get_string( array( 'amp', 'url_type' ) ) == 'querystring' &&
				$query == $c->get_string( array( 'amp', 'url_postfix' ) ) ) {
			$query_rules[1] = str_replace( '[E=', '[E=W3TC_AMP:_amp,E=', $query_rules[1] );
		}

		return $query_rules;
	}



	public function w3tc_pagecache_rules_apache_uri_prefix( $uri_prefix ) {
		$c = Dispatcher::config();

		if ( $c->get_string( array( 'amp', 'url_type' ) ) == 'querystring' ) {
			$uri_prefix .= '%{ENV:W3TC_AMP}';
		}

		return $uri_prefix;
	}



	public function w3tc_pagecache_rules_nginx_accept_qs_rules( $query_rules, $query ) {
		$c = Dispatcher::config();

		if ( $c->get_string( array( 'amp', 'url_type' ) ) == 'querystring' &&
				$query == $c->get_string( array( 'amp', 'url_postfix' ) ) ) {
			array_splice( $query_rules, 1, 0, '    set $w3tc_amp "_amp";' );
			array_unshift( $query_rules, 'set $w3tc_amp "";' );
		}

		return $query_rules;
	}



	public function w3tc_pagecache_rules_nginx_uri_prefix( $uri_prefix ) {
		$c = Dispatcher::config();

		if ( $c->get_string( array( 'amp', 'url_type' ) ) == 'querystring' ) {
			$uri_prefix .= '$w3tc_amp';
		}

		return $uri_prefix;
	}
}



w3tc_add_action( 'pagecache_normalize_url_fragments',
	array( '\W3TC\Extension_Amp_Plugin', 'pagecache_normalize_url_fragments' ) );
w3tc_add_action( 'pagecache_page_key',
	array( '\W3TC\Extension_Amp_Plugin', 'pagecache_page_key' ) );
w3tc_add_action( 'wp_loaded',
	array( '\W3TC\Extension_Amp_Plugin', 'wp_loaded' ) );
