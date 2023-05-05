<?php
namespace W3TC;

/**
 * W3 PgCache plugin - administrative interface
 */




/**
 * class PgCache_Plugin_Admin
 */
class PgCache_Plugin_Admin {
	/**
	 * Config
	 */
	private $_config = null;

	function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Runs plugin
	 */
	function run() {
		add_filter( 'w3tc_save_options', array( $this, 'w3tc_save_options' ) );

		$config_labels = new PgCache_ConfigLabels();
		add_filter( 'w3tc_config_labels', array( $config_labels, 'config_labels' ) );

		if ( $this->_config->get_boolean( 'pgcache.enabled' ) ) {
			add_filter( 'w3tc_errors', array( $this, 'w3tc_errors' ) );
			add_filter( 'w3tc_usage_statistics_summary_from_history', array(
					$this, 'w3tc_usage_statistics_summary_from_history' ), 10, 2 );
		}

		// Cache groups.
		add_action(
			'w3tc_config_ui_save-w3tc_cachegroups',
			array(
				'\W3TC\CacheGroups_Plugin_Admin',
				'w3tc_config_ui_save_w3tc_cachegroups',
			),
			10,
			1
		);
	}

	function cleanup() {
		// We check to see if we're dealing with a cluster
		$config = Dispatcher::config();
		$is_cluster = $config->get_boolean( 'cluster.messagebus.enabled' );

		// If we are, we notify the subscribers. If not, we just cleanup in here
		if ( $is_cluster ) {
			$this->cleanup_cluster();
		} else {
			$this->cleanup_local();
		}

	}

	/**
	 * Will trigger notifications to be sent to the cluster to 'order' them to clean their page cache.
	 */
	function cleanup_cluster() {
		$sns_client = Dispatcher::component( 'Enterprise_CacheFlush_MakeSnsEvent' );
		$sns_client->pgcache_cleanup();
	}

	function cleanup_local() {
		$engine = $this->_config->get_string( 'pgcache.engine' );

		switch ( $engine ) {
		case 'file':
			$w3_cache_file_cleaner = new Cache_File_Cleaner( array(
					'cache_dir' => Util_Environment::cache_blog_dir( 'page' ),
					'clean_timelimit' => $this->_config->get_integer( 'timelimit.cache_gc' )
				) );

			$w3_cache_file_cleaner->clean();
			break;

		case 'file_generic':
			if ( Util_Environment::blog_id() == 0 )
				$flush_dir = W3TC_CACHE_PAGE_ENHANCED_DIR;
			else
				$flush_dir = W3TC_CACHE_PAGE_ENHANCED_DIR . '/' . Util_Environment::host();

			$w3_cache_file_cleaner_generic = new Cache_File_Cleaner_Generic( array(
					'exclude' => array(
						'.htaccess'
					),
					'cache_dir' => $flush_dir,
					'expire' => $this->_config->get_integer( 'browsercache.html.lifetime' ),
					'clean_timelimit' => $this->_config->get_integer( 'timelimit.cache_gc' )
				) );

			$w3_cache_file_cleaner_generic->clean();
			break;
		}
	}

	/**
	 * Prime cache
	 *
	 * @param integer $start
	 * @return void
	 */
	function prime( $start = null, $limit = null, $log_callback = null ) {
		if ( is_null( $start ) ) {
			$start = get_option( 'w3tc_pgcache_prime_offset' );
		}
		if ( $start < 0 ) {
			$start = 0;
		}

		$interval = $this->_config->get_integer( 'pgcache.prime.interval' );
		if ( is_null( $limit ) ) {
			$limit = $this->_config->get_integer( 'pgcache.prime.limit' );
		}
		if ( $limit < 1 ) {
			$limit = 1;
		}

		$sitemap = $this->_config->get_string( 'pgcache.prime.sitemap' );

		if ( !is_null( $log_callback ) ) {
			$log_callback( 'Priming from sitemap ' . $sitemap .
				' entries ' . ( $start + 1 ) . '..' . ( $start + $limit ) );
		}

		/**
		 * Parse XML sitemap
		 */
		$urls = $this->parse_sitemap( $sitemap );

		/**
		 * Queue URLs
		 */
		$queue = array_slice( $urls, $start, $limit );

		if ( count( $urls ) > ( $start + $limit ) ) {
			$next_offset = $start + $limit;
		} else {
			$next_offset = 0;
		}

		update_option( 'w3tc_pgcache_prime_offset', $next_offset, false );

		/**
		 * Make HTTP requests and prime cache
		 */

		// use 'WordPress' since by default we use W3TC-powered by
		// which blocks caching
		foreach ( $queue as $url ) {
			Util_Http::get( $url, array( 'user-agent' => 'WordPress' ) );

			if ( !is_null( $log_callback ) ) {
				$log_callback( 'Priming ' . $url );
			}
		}
	}

	/**
	 * Parses sitemap
	 *
	 * @param string  $url
	 * @return array
	 */
	function parse_sitemap( $url ) {
		if ( !Util_Environment::is_url( $url ) )
			$url = home_url( $url );

		$urls = array();
		$response = Util_Http::get( $url );

		if ( !is_wp_error( $response ) && $response['response']['code'] == 200 ) {
			$url_matches = null;
			$sitemap_matches = null;

			if ( preg_match_all( '~<sitemap>(.*?)</sitemap>~is', $response['body'], $sitemap_matches ) ) {
				$loc_matches = null;

				foreach ( $sitemap_matches[1] as $sitemap_match ) {
					if ( preg_match( '~<loc>(.*?)</loc>~is', $sitemap_match, $loc_matches ) ) {
						$loc = trim( $loc_matches[1] );

						if ( $loc ) {
							$urls = array_merge( $urls, $this->parse_sitemap( $loc ) );
						}
					}
				}
			} elseif ( preg_match_all( '~<url>(.*?)</url>~is', $response['body'], $url_matches ) ) {
				$locs = array();
				$loc_matches = null;
				$priority_matches = null;

				foreach ( $url_matches[1] as $url_match ) {
					$loc = '';
					$priority = 0.5;

					if ( preg_match( '~<loc>(.*?)</loc>~is', $url_match, $loc_matches ) ) {
						$loc = trim( $loc_matches[1] );
					}

					if ( preg_match( '~<priority>(.*?)</priority>~is', $url_match, $priority_matches ) ) {
						$priority = (double) trim( $priority_matches[1] );
					}

					if ( $loc && $priority ) {
						$locs[$loc] = $priority;
					}
				}

				arsort( $locs );

				$urls = array_keys( $locs );
			} elseif ( preg_match_all( '~<rss[^>]*>(.*?)</rss>~is', $response['body'], $sitemap_matches ) ) {

				// rss feed format
				if ( preg_match_all( '~<link[^>]*>(.*?)</link>~is', $response['body'], $url_matches ) ) {
					foreach ( $url_matches[1] as $url_match ) {
						$url = trim( $url_match );
						$cdata_matches = null;
						if ( preg_match( '~<!\[CDATA\[(.*)\]\]>~is', $url, $cdata_matches ) ) {
							$url = $cdata_matches[1];
						}

						$urls[] = $url;
					}
				}
			}
		}

		return $urls;
	}

	/**
	 * Makes get requests to url specific to a post, its permalink
	 *
	 * @param unknown $post_id
	 * @return boolean returns true on success
	 */
	public function prime_post( $post_id ) {
		$post_urls = Util_PageUrls::get_post_urls( $post_id );

		// Make HTTP requests and prime cache
		foreach ( $post_urls as $url ) {
			$result = Util_Http::get( $url, array( 'user-agent' => 'WordPress' ) );
			if ( is_wp_error( $result ) )
				return false;
		}
		return true;
	}



	public function w3tc_save_options( $data ) {
		$new_config = $data['new_config'];
		$old_config = $data['old_config'];

		if ( ( !$new_config->get_boolean( 'pgcache.cache.home' ) && $old_config->get_boolean( 'pgcache.cache.home' ) ) ||
			$new_config->get_boolean( 'pgcache.reject.front_page' ) && !$old_config->get_boolean( 'pgcache.reject.front_page' ) ||
			!$new_config->get_boolean( 'pgcache.cache.feed' ) && $old_config->get_boolean( 'pgcache.cache.feed' ) ||
			!$new_config->get_boolean( 'pgcache.cache.query' ) && $old_config->get_boolean( 'pgcache.cache.query' ) ||
			!$new_config->get_boolean( 'pgcache.cache.ssl' ) && $old_config->get_boolean( 'pgcache.cache.ssl' ) ) {
			$state = Dispatcher::config_state();
			$state->set( 'common.show_note.flush_posts_needed', true );
			$state->save();
		}

		return $data;
	}

	public function w3tc_errors( $errors ) {
		$c = Dispatcher::config();

		if ( $c->get_string( 'pgcache.engine' ) == 'memcached' ) {
			$memcached_servers = $c->get_array( 'pgcache.memcached.servers' );

			if ( !Util_Installed::is_memcache_available( $memcached_servers ) ) {
				if ( !isset( $errors['memcache_not_responding.details'] ) )
					$errors['memcache_not_responding.details'] = array();

				$errors['memcache_not_responding.details'][] = sprintf(
					__( 'Page Cache: %s.', 'w3-total-cache' ),
					implode( ', ', $memcached_servers ) );
			}
		}

		return $errors;
	}

	public function w3tc_usage_statistics_summary_from_history( $summary, $history ) {
		// total size
		$g = Dispatcher::component( 'PgCache_ContentGrabber' );
		$pagecache = array();

		$e = $this->_config->get_string( 'pgcache.engine' );
		$pagecache['engine_name'] = Cache::engine_name( $e );
		$file_generic = ( $e == 'file_generic' );


		// build metrics in php block
		if ( !isset( $summary['php'] ) ) {
			$summary['php'] = array();
		}

		Util_UsageStatistics::sum_by_prefix_positive( $summary['php'],
			$history, 'php_requests_pagecache' );

		// need to return cache size
		if ( $file_generic ) {
			list( $v, $should_count ) =
				Util_UsageStatistics::get_or_init_size_transient(
				'w3tc_ustats_pagecache_size', $summary );
			if ( $should_count ) {
				$size = $g->get_cache_stats_size( $summary['timeout_time'] );
				$v['size_used'] = Util_UsageStatistics::bytes_to_size2(
					$size, 'bytes' );
				$v['items'] = Util_UsageStatistics::integer2(
					$size, 'items' );

				set_transient( 'w3tc_ustats_pagecache_size', $v, 55 );
			}

			if ( isset( $v['size_used'] ) ) {
				$pagecache['size_used'] = $v['size_used'];
				$pagecache['items'] = $v['items'];
			}

			if ( isset( $summary['access_log'] ) ) {
				$pagecache['requests'] = $summary['access_log']['dynamic_requests_total_v'];
				$pagecache['requests_hit'] = $pagecache['requests'] - $summary['php']['php_requests_v'];
				if ($pagecache['requests_hit'] < 0) {
					$pagecache['requests_hit'] = 0;
				}
			}
		} else {
			// all request counts data available
			$pagecache['requests'] = $summary['php']['php_requests_v'];
			$pagecache['requests_hit'] =
				isset( $summary['php']['php_requests_pagecache_hit'] ) ?
				$summary['php']['php_requests_pagecache_hit'] : 0;

			$requests_time_ms = Util_UsageStatistics::sum( $history,
				'pagecache_requests_time_10ms' ) * 10;
			$php_requests = Util_UsageStatistics::sum( $history,
				'php_requests' );

			if ( $php_requests > 0 ) {
				$pagecache['request_time_ms'] = Util_UsageStatistics::integer(
					$requests_time_ms / $php_requests );
			}
		}

		if ( $e == 'memcached' ) {
			$pagecache['size_percent'] = $summary['memcached']['size_percent'];
		}
		if ( isset($pagecache['requests_hit'] ) ) {
			$pagecache['requests_hit_rate'] = Util_UsageStatistics::percent(
				$pagecache['requests_hit'], $pagecache['requests'] );
		}

		if ( !isset( $summary['php']['php_requests_pagecache_hit'] ) ) {
			$summary['php']['php_requests_pagecache_hit'] = 0;
		}

		if ( isset( $summary['php']['php_requests_v'] ) ) {
			$v = $summary['php']['php_requests_v'] -
				$summary['php']['php_requests_pagecache_hit'];
			if ( $v < 0 ) {
				$v = 0;
			}

			$summary['php']['php_requests_pagecache_miss'] = $v;
		}

		if ( isset( $pagecache['requests'] ) ) {
			$pagecache['requests_per_second'] =
				Util_UsageStatistics::value_per_period_seconds( $pagecache['requests'], $summary );
		}


		$summary['pagecache'] = $pagecache;

		return $summary;
	}
}
