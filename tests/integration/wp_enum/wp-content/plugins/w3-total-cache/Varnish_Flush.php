<?php
namespace W3TC;

/**
 * Class Varnish_Flush
 */
class Varnish_Flush {
	/**
	 * Debug flag
	 *
	 * @var bool
	 */
	var $_debug = false;

	/**
	 * Varnish servers
	 *
	 * @var array
	 */
	var $_servers = array();

	/**
	 * Operation timeout
	 *
	 * @var int
	 */
	var $_timeout = 30;

	/**
	 * Advanced cache config
	 */
	var $_config = null;

	/**
	 * Array of already flushed urls
	 *
	 * @var array
	 */
	private $queued_urls = array();
	private $flush_operation_requested = false;

	/**
	 * PHP5-style constructor
	 */
	function __construct() {
		$this->_config = Dispatcher::config();

		$this->_debug = $this->_config->get_boolean( 'varnish.debug' );
		$this->_servers = $this->_config->get_array( 'varnish.servers' );
		$this->_timeout = $this->_config->get_integer( 'timelimit.varnish_purge' );
	}

	/**
	 * Purge URI
	 *
	 * @param string  $url
	 * @return boolean
	 */
	protected function _purge( $url ) {
		@set_time_limit( $this->_timeout );
		$return = true;

		foreach ( (array) $this->_servers as $server ) {
			$response = $this->_request( $server, $url );

			if ( is_wp_error( $response ) ) {
				$this->_log( $url, sprintf( 'Unable to send request: %s.', implode( '; ', $response->get_error_messages() ) ) );
				$return = false;
			} elseif ( $response['response']['code'] !== 200 ) {
				$this->_log( $url, 'Bad response: ' . $response['response']['status'] );
				$return = false;
			} else {
				$this->_log( $url, 'PURGE OK' );
			}
		}

		return $return;
	}

	/*
	 * Sends purge request. Cannt use default wp HTTP implementation
	 * if we send request to different host than specified in $url
	 *
	 * @param $url string
	 */
	function _request( $varnish_server, $url ) {
		$parse_url = @parse_url( $url );

		if ( !$parse_url || !isset( $parse_url['host'] ) )
			return new \WP_Error( 'http_request_failed', 'Unrecognized URL format ' . $url );

		$host = $parse_url['host'];
		$port = ( isset( $parse_url['port'] ) ? (int) $parse_url['port'] : 80 );
		$path = ( !empty( $parse_url['path'] ) ? $parse_url['path'] : '/' );
		$query = ( isset( $parse_url['query'] ) ? $parse_url['query'] : '' );
		$request_uri = $path . ( $query != '' ? '?' . $query : '' );

		list( $varnish_host, $varnish_port ) =
			Util_Content::endpoint_to_host_port( $varnish_server, 80 );

		// if url host is the same as varnish server - we can use regular
		// wordpress http infrastructure, otherwise custom request should be
		// sent using fsockopen, since we send request to other server than
		// specified by $url
		if ( $host == $varnish_host && $port == $varnish_port )
			return Util_Http::request( $url, array( 'method' => 'PURGE' ) );

		$request_headers_array = array(
			sprintf( 'PURGE %s HTTP/1.1', $request_uri ),
			sprintf( 'Host: %s', $host ),
			sprintf( 'User-Agent: %s', W3TC_POWERED_BY ),
			'Connection: close'
		);

		$request_headers = implode( "\r\n", $request_headers_array );
		$request = $request_headers . "\r\n\r\n";

		// log what we are about to do
		$this->_log( $url, sprintf( 'Connecting to %s ...', $varnish_host ) );
		$this->_log( $url, sprintf( 'PURGE %s HTTP/1.1', $request_uri ) );
		$this->_log( $url, sprintf( 'Host: %s', $host ) );

		$errno = null;
		$errstr = null;
		$fp = @fsockopen( $varnish_host, $varnish_port, $errno, $errstr, 10 );
		if ( !$fp )
			return new \WP_Error( 'http_request_failed', $errno . ': ' . $errstr );

		@stream_set_timeout( $fp, 60 );

		@fputs( $fp, $request );

		$response = '';
		while ( !@feof( $fp ) )
			$response .= @fgets( $fp, 4096 );

		@fclose( $fp );

		list( $response_headers, $contents ) = explode( "\r\n\r\n", $response, 2 );
		$matches = null;
		if ( preg_match( '~^HTTP/1.[01] (\d+)~', $response_headers, $matches ) ) {
			$code = (int)$matches[1];
			$a = explode( "\n", $response_headers );
			$status = ( count( $a ) >= 1 ? $a[0] : '' );
			$return = array(
				'response' => array(
					'code' => $code,
					'status' => $status
				)
			);
			return $return;
		}

		return new \WP_Error( 'http_request_failed',
			'Unrecognized response header' . $response_headers );
	}

	/**
	 * Write log entry
	 *
	 * @param string  $url
	 * @param string  $msg
	 * @return bool|int
	 */
	function _log( $url, $msg ) {
		if ( $this->_debug ) {
			$data = sprintf( "[%s] [%s] %s\n", date( 'r' ), $url, $msg );
			$data = strtr( $data, '<>', '' );

			$filename = Util_Debug::log_filename( 'varnish' );

			return @file_put_contents( $filename, $data, FILE_APPEND );
		}

		return true;
	}



	/**
	 * Flush varnish cache
	 */
	function flush() {
		$this->flush_operation_requested = true;
		return true;
	}

	private function do_flush() {
		if ( !is_network_admin() ) {
			$full_urls = array( get_home_url() . '/.*' );
			$full_urls = Util_PageUrls::complement_with_mirror_urls(
				$full_urls );

			foreach ( $full_urls as $url )
				$this->_purge( $url );
		} else {
			// todo: remove. doesnt work for all caches.
			// replace with tool to flush network
			global $wpdb;
			$protocall = Util_Environment::is_https() ? 'https://' : 'http://';

			// If WPMU Domain Mapping plugin is installed and active
			if ( defined( 'SUNRISE_LOADED' ) && SUNRISE_LOADED && isset( $wpdb->dmtable ) && !empty( $wpdb->dmtable ) ) {
				$blogs = $wpdb->get_results( "
					SELECT {$wpdb->blogs}.domain, {$wpdb->blogs}.path, {$wpdb->dmtable}.domain AS mapped_domain
					FROM {$wpdb->dmtable}
					RIGHT JOIN {$wpdb->blogs} ON {$wpdb->dmtable}.blog_id = {$wpdb->blogs}.blog_id
					WHERE site_id = {$wpdb->siteid}
					AND spam = 0
					AND deleted = 0
					AND archived = '0'" );
				foreach ( $blogs as $blog ) {
					if ( !isset( $blog->mapped_domain ) )
						$url = $protocall . $blog->domain . ( strlen( $blog->path )>1? '/' . trim( $blog->path, '/' ) : '' ) . '/.*';
					else
						$url = $protocall . $blog->mapped_domain . '/.*';
					$this->_purge( $url );
				}

			}else {
				if ( !Util_Environment::is_wpmu_subdomain() ) {
					$this->_purge( get_home_url().'/.*' );
				} else {
					$blogs = $wpdb->get_results( "
						SELECT domain, path
						FROM {$wpdb->blogs}
						WHERE site_id = '{$wpdb->siteid}'
						AND spam = 0
						AND deleted = 0
						AND archived = '0'" );

					foreach ( $blogs as $blog ) {
						$url = $protocall . $blog->domain . ( strlen( $blog->path )>1? '/' . trim( $blog->path, '/' ) : '' ) . '/.*';
						$this->_purge( $url );
					}
				}
			}
		}
	}

	/**
	 * Flushes varnish post cache
	 *
	 * @param integer $post_id Post ID.
	 * @param boolean $force   Force flag (optional).
	 *
	 * @return boolean
	 */
	function flush_post( $post_id, $force ) {
		if ( !$post_id ) {
			$post_id = Util_Environment::detect_post_id();
		}

		if ( $post_id ) {
			$full_urls = array();

			$post = null;
			$terms = array();

			$feeds = $this->_config->get_array( 'pgcache.purge.feed.types' );
			$limit_post_pages = $this->_config->get_integer( 'pgcache.purge.postpages_limit' );

			if ( $this->_config->get_boolean( 'pgcache.purge.terms' ) || $this->_config->get_boolean( 'varnish.pgcache.feed.terms' ) ) {
				$taxonomies = get_post_taxonomies( $post_id );
				$terms = wp_get_post_terms( $post_id, $taxonomies );
			}

			switch ( true ) {
			case $this->_config->get_boolean( 'pgcache.purge.author' ):
			case $this->_config->get_boolean( 'pgcache.purge.archive.daily' ):
			case $this->_config->get_boolean( 'pgcache.purge.archive.monthly' ):
			case $this->_config->get_boolean( 'pgcache.purge.archive.yearly' ):
			case $this->_config->get_boolean( 'pgcache.purge.feed.author' ):
				$post = get_post( $post_id );
			}

			$front_page = get_option( 'show_on_front' );

			/**
			 * Home (Frontpage) URL
			 */
			if ( ( $this->_config->get_boolean( 'pgcache.purge.home' ) && $front_page == 'posts' )||
				$this->_config->get_boolean( 'pgcache.purge.front_page' ) ) {
				$full_urls = array_merge( $full_urls,
					Util_PageUrls::get_frontpage_urls( $limit_post_pages ) );
			}

			/**
			 * Home (Post page) URL
			 */
			if ( $this->_config->get_boolean( 'pgcache.purge.home' ) && $front_page != 'posts' ) {
				$full_urls = array_merge( $full_urls,
					Util_PageUrls::get_postpage_urls( $limit_post_pages ) );
			}

			/**
			 * Post URL
			 */
			if ( $this->_config->get_boolean( 'pgcache.purge.post' ) || $force ) {
				$full_urls = array_merge( $full_urls, Util_PageUrls::get_post_urls( $post_id ) );
			}

			/**
			 * Post comments URLs
			 */
			if ( $this->_config->get_boolean( 'pgcache.purge.comments' ) && function_exists( 'get_comments_pagenum_link' ) ) {
				$full_urls = array_merge( $full_urls, Util_PageUrls::get_post_comments_urls( $post_id ) );
			}

			/**
			 * Post author URLs
			 */
			if ( $this->_config->get_boolean( 'pgcache.purge.author' ) && $post ) {
				$full_urls = array_merge( $full_urls, Util_PageUrls::get_post_author_urls( $post->post_author, $limit_post_pages ) );
			}

			/**
			 * Post terms URLs
			 */
			if ( $this->_config->get_boolean( 'pgcache.purge.terms' ) ) {
				$full_urls = array_merge( $full_urls, Util_PageUrls::get_post_terms_urls( $terms, $limit_post_pages ) );
			}

			/**
			 * Daily archive URLs
			 */
			if ( $this->_config->get_boolean( 'pgcache.purge.archive.daily' ) && $post ) {
				$full_urls = array_merge( $full_urls, Util_PageUrls::get_daily_archive_urls( $post, $limit_post_pages ) );
			}

			/**
			 * Monthly archive URLs
			 */
			if ( $this->_config->get_boolean( 'pgcache.purge.archive.monthly' ) && $post ) {
				$full_urls = array_merge( $full_urls, Util_PageUrls::get_monthly_archive_urls( $post, $limit_post_pages ) );
			}

			/**
			 * Yearly archive URLs
			 */
			if ( $this->_config->get_boolean( 'pgcache.purge.archive.yearly' ) && $post ) {
				$full_urls = array_merge( $full_urls, Util_PageUrls::get_yearly_archive_urls( $post, $limit_post_pages ) );
			}

			/**
			 * Feed URLs
			 */
			if ( $this->_config->get_boolean( 'pgcache.purge.feed.blog' ) ) {
				$full_urls = array_merge( $full_urls,
					Util_PageUrls::get_feed_urls( $feeds ) );
			}

			if ( $this->_config->get_boolean( 'pgcache.purge.feed.comments' ) ) {
				$full_urls = array_merge( $full_urls, Util_PageUrls::get_feed_comments_urls( $post_id, $feeds ) );
			}

			if ( $this->_config->get_boolean( 'pgcache.purge.feed.author' ) && $post ) {
				$full_urls = array_merge( $full_urls, Util_PageUrls::get_feed_author_urls( $post->post_author, $feeds ) );
			}

			if ( $this->_config->get_boolean( 'pgcache.purge.feed.terms' ) ) {
				$full_urls = array_merge( $full_urls, Util_PageUrls::get_feed_terms_urls( $terms, $feeds ) );
			}

			/**
			 * Purge selected pages
			 */
			if ( $this->_config->get_array( 'pgcache.purge.pages' ) ) {
				$pages = $this->_config->get_array( 'pgcache.purge.pages' );
				$full_urls = array_merge( $full_urls, Util_PageUrls::get_pages_urls( $pages ) );
			}

			if ( $this->_config->get_string( 'pgcache.purge.sitemap_regex' ) ) {
				$sitemap_regex = $this->_config->get_string( 'pgcache.purge.sitemap_regex' );
				$full_urls[] = Util_Environment::home_domain_root_url() . '/' . trim( $sitemap_regex, "^$" );
			}

			// add mirror urls
			$full_urls = Util_PageUrls::complement_with_mirror_urls(
				$full_urls );

			$full_urls = apply_filters( 'varnish_flush_post_queued_urls',
				$full_urls );

			/**
			 * Queue flush
			 */
			if ( count( $full_urls ) ) {
				foreach ( $full_urls as $url )
					$this->queued_urls[$url] = '*';
			}

			return true;
		}

		return false;
	}

	/**
	 * Flush a single url
	 *
	 * @param unknown $url
	 */
	function flush_url( $url ) {
		$this->_purge( $url );
	}

	/**
	 * Flushes global and repeated urls
	 */
	function flush_post_cleanup() {
		if ( $this->flush_operation_requested ) {
			$this->do_flush();
			$count = 999;

			$this->flush_operation_requested = false;
			$this->queued_urls = array();
		} else {
			$count = count( $this->queued_urls );
			if ( $count > 0 ) {
				foreach ( $this->queued_urls as $url => $nothing )
					$this->flush_url( $url );

				$this->queued_urls = array();
			}
		}

		return $count;
	}
}
