<?php
namespace W3TC;

/**
 * W3 ObjectCache plugin
 */
class BrowserCache_Plugin {
	private $_config = null;
	private $browsercache_rewrite;

	function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Runs plugin
	 */
	function run() {
		add_filter( 'w3tc_admin_bar_menu',
			array( $this, 'w3tc_admin_bar_menu' ) );

		if ( $this->_config->get_boolean( 'browsercache.html.w3tc' ) ) {
			add_action( 'send_headers',
				array( $this, 'send_headers' ) );
		}

		if ( !$this->_config->get_boolean( 'browsercache.html.etag' ) ) {
			add_filter( 'wp_headers',
				array( $this, 'filter_wp_headers' ),
				0, 2 );
		}

		$url_uniqualize_enabled = $this->url_uniqualize_enabled();

		if ( $this->url_clean_enabled() || $url_uniqualize_enabled ) {
			$this->browsercache_rewrite =
				$this->_config->get_boolean( 'browsercache.rewrite' );

			// modify CDN urls
			add_filter( 'w3tc_cdn_url',
				array( $this, 'w3tc_cdn_url' ), 0, 3 );

			if ( $url_uniqualize_enabled ) {
				add_action( 'w3tc_flush_all',
					array( $this, 'w3tc_flush_all' ), 1050, 1 );
			}


			if ( $this->can_ob() ) {
				Util_Bus::add_ob_callback( 'browsercache',
					array( $this, 'ob_callback' ) );
			}
		}

		$v = $this->_config->get_string( 'browsercache.security.session.cookie_httponly' );
		if ( !empty( $v ) ) {
			@ini_set( 'session.cookie_httponly', $v == 'on' ? '1': '0' );
		}
		$v = $this->_config->get_string( 'browsercache.security.session.cookie_secure' );
		if ( !empty( $v ) ) {
			@ini_set( 'session.cookie_secure', $v == 'on' ? '1': '0' );
		}
		$v = $this->_config->get_string( 'browsercache.security.session.use_only_cookies' );
		if ( !empty( $v ) ) {
			@ini_set( 'session.use_only_cookies', $v == 'on' ? '1': '0' );
		}

		add_filter( 'w3tc_minify_http2_preload_url',
			array( $this, 'w3tc_minify_http2_preload_url' ), 4000 );
		add_filter( 'w3tc_cdn_config_headers',
			array( $this, 'w3tc_cdn_config_headers' ) );

		if ( Util_Admin::is_w3tc_admin_page() ) {
			add_action( 'admin_notices', array( $this, 'admin_notices' ) );
		}
	}

	private function url_clean_enabled() {
		return
			$this->_config->get_boolean( 'browsercache.cssjs.querystring' ) ||
			$this->_config->get_boolean( 'browsercache.html.querystring' ) ||
			$this->_config->get_boolean( 'browsercache.other.querystring' );
	}

	private function url_uniqualize_enabled() {
		return $this->_config->get_boolean( 'browsercache.cssjs.replace' ) ||
			$this->_config->get_boolean( 'browsercache.html.replace' ) ||
			$this->_config->get_boolean( 'browsercache.other.replace' );
	}

	public function w3tc_flush_all( $extras = array() ) {
		if ( isset( $extras['only'] ) && $extras['only'] != 'browsercache' )
			return;

		update_option( 'w3tc_browsercache_flush_timestamp',
			rand( 10000, 99999 ) . '' );
	}

	/**
	 * Check if we can start OB
	 *
	 * @return boolean
	 */
	function can_ob() {
		/**
		 * Skip if admin
		 */
		if ( defined( 'WP_ADMIN' ) ) {
			return false;
		}

		/**
		 * Skip if doing AJAX
		 */
		if ( defined( 'DOING_AJAX' ) ) {
			return false;
		}

		/**
		 * Skip if doing cron
		 */
		if ( defined( 'DOING_CRON' ) ) {
			return false;
		}

		/**
		 * Skip if APP request
		 */
		if ( defined( 'APP_REQUEST' ) ) {
			return false;
		}

		/**
		 * Skip if XMLRPC request
		 */
		if ( defined( 'XMLRPC_REQUEST' ) ) {
			return false;
		}

		/**
		 * Check for WPMU's and WP's 3.0 short init
		 */
		if ( defined( 'SHORTINIT' ) && SHORTINIT ) {
			return false;
		}

		/**
		 * Check User Agent
		 */
		$http_user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		if ( stristr( $http_user_agent, W3TC_POWERED_BY ) !== false ) {
			return false;
		}

		return true;
	}

	/**
	 * Output buffer callback
	 *
	 * @param string  $buffer
	 * @return mixed
	 */
	function ob_callback( $buffer ) {
		if ( $buffer != '' && Util_Content::is_html_xml( $buffer ) ) {
			$domain_url_regexp = Util_Environment::home_domain_root_url_regexp();

			$buffer = preg_replace_callback(
				'~(href|src|action|extsrc|asyncsrc|w3tc_load_js\()=?([\'"])((' .
				$domain_url_regexp .
				')?(/[^\'"/][^\'"]*\.([a-z-_]+)([\?#][^\'"]*)?))[\'"]~Ui', array(
					$this,
					'link_replace_callback'
				), $buffer );

			// without quotes
			$buffer = preg_replace_callback(
				'~(href|src|action|extsrc|asyncsrc)=((' .
				$domain_url_regexp .
				')?(/[^\\s>][^\\s>]*\.([a-z-_]+)([\?#][^\\s>]*)?))([\\s>])~Ui', array(
					$this,
					'link_replace_callback_noquote'
				), $buffer );
		}

		return $buffer;
	}

	/**
	 * Link replace callback
	 *
	 * @param string  $matches
	 * @return string
	 */
	function link_replace_callback( $matches ) {
		list ( $match, $attr, $quote, $url, , , , , $extension ) = $matches;

		$ops = $this->_get_url_mutation_operations( $url, $extension );
		if ( is_null( $ops ) )
			return $match;

		$url = $this->mutate_url( $url, $ops, !$this->browsercache_rewrite );

		if ( $attr != 'w3tc_load_js(' )
			return $attr . '=' . $quote . $url . $quote;
		return sprintf( '%s\'%s\'', $attr, $url );
	}

	/**
	 * Link replace callback when no quote arount attribute value
	 *
	 * @param string  $matches
	 * @return string
	 */
	function link_replace_callback_noquote( $matches ) {
		list ( $match, $attr, $url, , , , , $extension, , $delimiter ) = $matches;

		$ops = $this->_get_url_mutation_operations( $url, $extension );
		if ( is_null( $ops ) )
			return $match;

		$url = $this->mutate_url( $url, $ops, !$this->browsercache_rewrite );

		return $attr . '=' . $url . $delimiter;
	}

	/**
	 * Mutate http/2 header links
	 */
	public function w3tc_minify_http2_preload_url( $data ) {
		if ( isset( $data['browsercache_processed'] ) ) {
			return $data;
		}

		$data['browsercache_processed'] = '*';
		$url = $data['result_link'];

		// decouple extension
		$matches = array();
		if ( !preg_match( '/\.([a-zA-Z0-9]+)($|[\?])/', $url, $matches ) ) {
			return $data;
		}
		$extension = $matches[1];

		$ops = $this->_get_url_mutation_operations( $url, $extension );
		if ( is_null( $ops ) ) {
			return $data;
		}

		$mutate_by_querystring = !$this->browsercache_rewrite;

		$url = $this->mutate_url( $url, $ops, $mutate_by_querystring );
		$data['result_link'] = $url;
		return $data;
	}

	/**
	 * Link replace for CDN url
	 *
	 * @param string  $matches
	 * @return string
	 */
	function w3tc_cdn_url( $url, $original_url, $is_cdn_mirror ) {
		// decouple extension
		$matches = array();
		if ( !preg_match( '/\.([a-zA-Z0-9]+)($|[\?])/', $original_url, $matches ) )
			return $url;
		$extension = $matches[1];

		$ops = $this->_get_url_mutation_operations( $original_url, $extension );
		if ( is_null( $ops ) )
			return $url;

		// for push cdns each flush would require manual reupload of files
		$mutate_by_querystring = !$this->browsercache_rewrite || !$is_cdn_mirror;

		$url = $this->mutate_url( $url, $ops, $mutate_by_querystring );
		return $url;
	}

	private function mutate_url( $url, $ops, $mutate_by_querystring ) {
		$query_pos = strpos( $url, '?' );
		if ( isset( $ops['querystring'] ) && $query_pos !== false ) {
			$url = substr( $url, 0, $query_pos );
			$query_pos = false;
		}

		if ( isset( $ops['replace'] ) ) {
			$id = $this->get_filename_uniqualizator();

			if ( $mutate_by_querystring ) {
				if ( $query_pos !== false ) {
					$url = substr( $url, 0, $query_pos + 1 ) . $id . '&amp;' .
						substr( $url, $query_pos + 1 );
				} else {
					$tag_pos = strpos( $url, '#' );
					if ( $tag_pos === false ) {
						$url .= '?' . $id;
					} else {
						$url = substr( $url, 0, $tag_pos ) . '?' . $id .
							substr( $url, $tag_pos );
					}
				}

			} else {
				// add $id to url before extension

				$url_query = '';
				if ( $query_pos !== false ) {
					$url_query = substr( $url, $query_pos );
					$url = substr( $url, 0, $query_pos );
				}

				$ext_pos = strrpos( $url, '.' );
				$extension = substr( $url, $ext_pos );

				$url = substr( $url, 0, strlen( $url ) - strlen( $extension ) ) .
					'.' . $id . $extension . $url_query;
			}
		}

		return $url;
	}

	function _get_url_mutation_operations( $url, $extension ) {
		static $extensions = null;
		if ( $extensions === null ) {
			$core = Dispatcher::component( 'BrowserCache_Core' );
			$extensions = $core->get_replace_querystring_extensions( $this->_config );
		}

		static $exceptions = null;
		if ( $exceptions === null )
			$exceptions = $this->_config->get_array( 'browsercache.replace.exceptions' );

		if ( !isset( $extensions[$extension] ) )
			return null;

		$test_url = Util_Environment::remove_query( $url );
		foreach ( $exceptions as $exception ) {
			$escaped = str_replace( '~', '\~', $exception );
			if ( trim( $exception ) && preg_match( '~' . $escaped . '~', $test_url ) )
				return null;
		}

		return $extensions[$extension];
	}

	/**
	 * Returns replace ID
	 *
	 * @return string
	 */
	function get_filename_uniqualizator() {
		static $cache_id = null;

		if ( $cache_id === null ) {
			$value = get_option( 'w3tc_browsercache_flush_timestamp' );

			if ( empty( $value ) ) {
				$value = rand( 10000, 99999 ) . '';
				update_option( 'w3tc_browsercache_flush_timestamp', $value );
			}

			$cache_id = substr( $value, 0, 5 );
		}

		return 'x' . $cache_id;
	}

	public function w3tc_admin_bar_menu( $menu_items ) {
		$browsercache_update_media_qs =
			( $this->_config->get_boolean( 'browsercache.cssjs.replace' ) ||
			$this->_config->get_boolean( 'browsercache.other.replace' ) );

		if ( $browsercache_update_media_qs ) {
			$menu_items['20190.browsercache'] = array(
				'id' => 'w3tc_flush_browsercache',
				'parent' => 'w3tc_flush',
				'title' => __( 'Browser Cache: Update Media Query String', 'w3-total-cache' ),
				'href' => wp_nonce_url( admin_url(
						'admin.php?page=w3tc_dashboard&amp;w3tc_flush_browser_cache' ),
					'w3tc' )
			);
		}

		return $menu_items;
	}

	/**
	 * Send headers
	 */
	function send_headers() {
		@header( 'X-Powered-By: ' . Util_Environment::w3tc_header() );
	}

	/**
	 * Returns headers config for CDN
	 */
	function w3tc_cdn_config_headers( $config ) {
		$sections = Util_Mime::sections_to_mime_types_map();
		foreach ( $sections as $section => $v ) {
			$config[$section] = $this->w3tc_cdn_config_headers_section( $section );
		}

		return $config;
	}

	private function w3tc_cdn_config_headers_section( $section ) {
		$c = $this->_config;
		$prefix = 'browsercache.' . $section;
		$lifetime = $c->get_integer( $prefix . '.lifetime' );

		$headers = array();

		if ( $c->get_boolean( $prefix . '.w3tc' ) ) {
			$headers['X-Powered-By'] = Util_Environment::w3tc_header();
		}

		if ( $c->get_boolean( $prefix . '.cache.control' ) ) {
			switch ( $c->get_string( $prefix . '.cache.policy' ) ) {
			case 'cache':
				$headers['Pragma'] = 'public';
				$headers['Cache-Control'] = 'public';
				break;

			case 'cache_public_maxage':
				$headers['Pragma'] = 'public';
				$headers['Cache-Control'] = "max-age=$lifetime, public";
				break;

			case 'cache_validation':
				$headers['Pragma'] = 'public';
				$headers['Cache-Control'] = 'public, must-revalidate, proxy-revalidate';
				break;

			case 'cache_noproxy':
				$headers['Pragma'] = 'public';
				$headers['Cache-Control'] = 'private, must-revalidate';
				break;

			case 'cache_maxage':
				$headers['Pragma'] = 'public';
				$headers['Cache-Control'] = "max-age=$lifetime, public, must-revalidate, proxy-revalidate";
				break;

			case 'no_cache':
				$headers['Pragma'] = 'no-cache';
				$headers['Cache-Control'] = 'max-age=0, private, no-store, no-cache, must-revalidate';
				break;
			}
		}

		return array(
			'etag' => $c->get_boolean( $prefix . 'etag' ),
			'expires' => $c->get_boolean( $prefix . '.expires' ),
			'lifetime' => $lifetime,
			'static' => $headers
		);
	}

	/**
	 * Filters headers set by WordPress
	 *
	 * @param unknown $headers
	 * @param unknown $wp
	 * @return
	 */
	function filter_wp_headers( $headers, $wp ) {
		if ( !empty( $wp->query_vars['feed'] ) )
			unset( $headers['ETag'] );
		return $headers;
	}

	/**
	 * Admin notice for Content-Security-Policy-Report-Only that displays if the feature is enabled and the report-uri/to isn't defined.
	 *
	 * @since 2.2.13
	 */
	public function admin_notices() {
		if ( $this->_config->get_boolean( 'browsercache.security.cspro' ) && empty( $this->_config->get_string( 'browsercache.security.cspro.reporturi' ) ) && empty( $this->_config->get_string( 'browsercache.security.cspro.reportto' ) ) ) {
			$message = '<p>' . sprintf(
				// translators: 1 opening HTML a tag to Browser Cache CSP-Report-Only settings, 2 closing HTML a tag.
				esc_html__(
					'The Content Security Policy - Report Only requires the "report-uri" and/or "report-to" directives. Please define one or both of these directives %1$shere%2$s.',
					'w3-total-cache'
				),
				'<a href="' . Util_Ui::admin_url( 'admin.php?page=w3tc_browsercache#browsercache__security__cspro' ) . '" target="_blank" alt="' . esc_attr__( 'Browser Cache Content-Security-Policy-Report-Only Settings', 'w3-total-cache' ) . '">',
				'</a>'
			);
			Util_Ui::error_box( $message );
		}
	}
}
