<?php
/**
 * File: PgCache_Plugin.php
 *
 * @package W3TC
 *
 * phpcs:disable PSR2.Classes.PropertyDeclaration.Underscore
 */

namespace W3TC;

/**
 * W3 PgCache plugin
 */
class PgCache_Plugin {
	/**
	 * Config.
	 *
	 * @var array
	 */
	private $_config = null;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Runs plugin
	 */
	public function run() {
		add_action( 'w3tc_flush_all', array( $this, 'w3tc_flush_posts' ), 1100, 1 );
		add_action( 'w3tc_flush_group', array( $this, 'w3tc_flush_group' ), 1100, 2 );
		add_action( 'w3tc_flush_post', array( $this, 'w3tc_flush_post' ), 1100, 2 );
		add_action( 'w3tc_flushable_posts', '__return_true', 1100 );
		add_action( 'w3tc_flush_posts', array( $this, 'w3tc_flush_posts' ), 1100 );
		add_action( 'w3tc_flush_url', array( $this, 'w3tc_flush_url' ), 1100, 1 );

		add_filter( 'w3tc_pagecache_set_header', array( $this, 'w3tc_pagecache_set_header' ), 10, 3 );
		add_filter( 'w3tc_admin_bar_menu', array( $this, 'w3tc_admin_bar_menu' ) );

		// phpcs:ignore WordPress.WP.CronInterval.ChangeDetected
		add_filter( 'cron_schedules', array( $this, 'cron_schedules' ) );

		add_action( 'w3tc_config_save', array( $this, 'w3tc_config_save' ), 10, 1 );

		$o = Dispatcher::component( 'PgCache_ContentGrabber' );

		add_filter( 'w3tc_footer_comment', array( $o, 'w3tc_footer_comment' ) );

		// usage statistics handling.
		add_action( 'w3tc_usage_statistics_of_request', array( $o, 'w3tc_usage_statistics_of_request' ), 10, 1 );
		add_filter( 'w3tc_usage_statistics_metrics', array( $this, 'w3tc_usage_statistics_metrics' ) );
		add_filter( 'w3tc_usage_statistics_sources', array( $this, 'w3tc_usage_statistics_sources' ) );

		if ( 'file' === $this->_config->get_string( 'pgcache.engine' ) ||
			'file_generic' === $this->_config->get_string( 'pgcache.engine' ) ) {
			add_action( 'w3_pgcache_cleanup', array( $this, 'cleanup' ) );
		}

		add_action( 'w3_pgcache_prime', array( $this, 'prime' ) );

		Util_AttachToActions::flush_posts_on_actions();

		add_filter( 'comment_cookie_lifetime', array( $this, 'comment_cookie_lifetime' ) );

		if ( 'file_generic' === $this->_config->get_string( 'pgcache.engine' ) ) {
			add_action( 'wp_logout', array( $this, 'on_logout' ), 0 );
			add_action( 'wp_login', array( $this, 'on_login' ), 0 );
		}

		if ( $this->_config->get_boolean( 'pgcache.prime.post.enabled', false ) ) {
			add_action( 'publish_post', array( $this, 'prime_post' ), 30 );
		}

		if ( ( $this->_config->get_boolean( 'pgcache.late_init' ) ||
			$this->_config->get_boolean( 'pgcache.late_caching' ) ) &&
			! is_admin() ) {
			$o = Dispatcher::component( 'PgCache_ContentGrabber' );
			add_action( 'init', array( $o, 'delayed_cache_print' ), 99999 );
		}

		if ( ! $this->_config->get_boolean( 'pgcache.mirrors.enabled' ) &&
			! Util_Environment::is_wpmu_subdomain() ) {
			add_action( 'init', array( $this, 'redirect_on_foreign_domain' ) );
		}
		if ( 'disable' === $this->_config->get_string( 'pgcache.rest' ) ) {
			// remove XMLRPC edit link.
			remove_action( 'xmlrpc_rsd_apis', 'rest_output_rsd' );
			// remove wp-json in <head>.
			remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
			// remove HTTP Header.
			remove_action( 'template_redirect', 'rest_output_link_header', 11 );

			add_filter( 'rest_authentication_errors', array( $this, 'rest_authentication_errors' ), 100 );
		}
	}

	/**
	 * Get authentication WP Error.
	 *
	 * @param mixed $result Result.
	 *
	 * @return WP_Error
	 */
	public function rest_authentication_errors( $result ) {
		$error_message = __( 'REST API disabled.', 'w3-total-cache' );

		return new \WP_Error( 'rest_disabled', $error_message, array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Does disk cache cleanup
	 *
	 * @return void
	 */
	public function cleanup() {
		$this->get_admin()->cleanup();
	}

	/**
	 * Prime cache
	 *
	 * @return void
	 */
	public function prime() {
		$this->get_admin()->prime();
	}

	/**
	 * Instantiates worker on demand
	 */
	private function get_admin() {
		return Dispatcher::component( 'PgCache_Plugin_Admin' );
	}

	/**
	 * Cron schedules filter
	 *
	 * @param array $schedules Schedules.
	 *
	 * @return array
	 */
	public function cron_schedules( $schedules ) {
		$c = $this->_config;

		if ( $c->get_boolean( 'pgcache.enabled' ) &&
			( 'file' === $c->get_string( 'pgcache.engine' ) ||
			'file_generic' === $c->get_string( 'pgcache.engine' ) ) ) {
			$v                               = $c->get_integer( 'pgcache.file.gc' );
			$schedules['w3_pgcache_cleanup'] = array(
				'interval' => $v,
				'display'  => sprintf(
					// translators: 1 interval in seconds.
					__( '[W3TC] Page Cache file GC (every %d seconds)', 'w3-total-cache' ),
					$v
				),
			);
		}

		if ( $c->get_boolean( 'pgcache.enabled' ) &&
			$c->get_boolean( 'pgcache.prime.enabled' ) ) {
			$v                             = $c->get_integer( 'pgcache.prime.interval' );
			$schedules['w3_pgcache_prime'] = array(
				'interval' => $v,
				'display'  => sprintf(
					// translators: 1 interval in seconds.
					__( '[W3TC] Page Cache prime (every %d seconds)', 'w3-total-cache' ),
					$v
				),
			);
		}

		return $schedules;
	}

	/**
	 * Redirect if foreign domain or WP_CLI.
	 */
	public function redirect_on_foreign_domain() {
		$request_host = Util_Environment::host();

		// host not known, potentially we are in console mode not http request.
		if ( empty( $request_host ) || defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		$home_url   = get_home_url();
		$parsed_url = @wp_parse_url( $home_url ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( isset( $parsed_url['host'] ) &&
			strtolower( $parsed_url['host'] ) !== strtolower( $request_host ) ) {
			$redirect_url = $parsed_url['scheme'] . '://';

			if ( ! empty( $parsed_url['user'] ) ) {
				$redirect_url .= $parsed_url['user'];
				if ( ! empty( $parsed_url['pass'] ) ) {
					$redirect_url .= ':' . $parsed_url['pass'];
				}
			}

			if ( ! empty( $parsed_url['host'] ) ) {
				$redirect_url .= $parsed_url['host'];
			}

			if ( ! empty( $parsed_url['port'] ) && 80 !== (int) $parsed_url['port'] ) {
				$redirect_url .= ':' . (int) $parsed_url['port'];
			}

			$redirect_url .= isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

			wp_safe_redirect( $redirect_url, 301 );

			exit();
		}
	}

	/**
	 * Get comment cookie lifetime
	 *
	 * @param integer $lifetime Comment cookie lifetime.
	 */
	public function comment_cookie_lifetime( $lifetime ) {
		$l = $this->_config->get_integer( 'pgcache.comment_cookie_ttl' );
		if ( -1 !== $l ) {
			return $l;
		} else {
			return $lifetime;
		}
	}

	/**
	 * Add cookie on logout to circumvent pagecache due to browser cache resulting in 304s
	 */
	public function on_logout() {
		setcookie( 'w3tc_logged_out' );
	}

	/**
	 * Remove logout cookie on logins
	 */
	public function on_login() {
		if ( isset( $_COOKIE['w3tc_logged_out'] ) ) {
			setcookie( 'w3tc_logged_out', '', 1 );
		}
	}

	/**
	 * Primes post.
	 *
	 * @param integer $post_id Post ID.
	 *
	 * @return boolean
	 */
	public function prime_post( $post_id ) {
		$w3_pgcache = Dispatcher::component( 'CacheFlush' );
		return $w3_pgcache->prime_post( $post_id );
	}

	/**
	 * Retrive usage statistics metrics
	 *
	 * @param array $metrics Metrics.
	 */
	public function w3tc_usage_statistics_metrics( $metrics ) {
		return array_merge(
			$metrics,
			array(
				'php_requests_pagecache_hit',
				'php_requests_pagecache_miss_404',
				'php_requests_pagecache_miss_ajax',
				'php_requests_pagecache_miss_api_call',
				'php_requests_pagecache_miss_configuration',
				'php_requests_pagecache_miss_fill',
				'php_requests_pagecache_miss_logged_in',
				'php_requests_pagecache_miss_mfunc',
				'php_requests_pagecache_miss_query_string',
				'php_requests_pagecache_miss_third_party',
				'php_requests_pagecache_miss_wp_admin',
				'pagecache_requests_time_10ms',
			)
		);
	}

	/**
	 * Usage Statisitcs sources filter.
	 *
	 * @param array $sources Sources.
	 *
	 * @return array
	 */
	public function w3tc_usage_statistics_sources( $sources ) {
		$c = Dispatcher::config();
		if ( 'apc' === $c->get_string( 'pgcache.engine' ) ) {
			$sources['apc_servers']['pgcache'] = array(
				'name' => __( 'Page Cache', 'w3-total-cache' ),
			);
		} elseif ( 'memcached' === $c->get_string( 'pgcache.engine' ) ) {
			$sources['memcached_servers']['pgcache'] = array(
				'servers'         => $c->get_array( 'pgcache.memcached.servers' ),
				'username'        => $c->get_string( 'pgcache.memcached.username' ),
				'password'        => $c->get_string( 'pgcache.memcached.password' ),
				'binary_protocol' => $c->get_boolean( 'pgcache.memcached.binary_protocol' ),
				'name'            => __( 'Page Cache', 'w3-total-cache' ),
			);
		} elseif ( 'redis' === $c->get_string( 'pgcache.engine' ) ) {
			$sources['redis_servers']['pgcache'] = array(
				'servers'                 => $c->get_array( 'pgcache.redis.servers' ),
				'verify_tls_certificates' => $c->get_boolean( 'pgcache.redis.verify_tls_certificates' ),
				'dbid'                    => $c->get_integer( 'pgcache.redis.dbid' ),
				'password'                => $c->get_string( 'pgcache.redis.password' ),
				'name'                    => __( 'Page Cache', 'w3-total-cache' ),
			);
		}

		return $sources;
	}

	/**
	 * Setup admin menu elements
	 *
	 * @param array $menu_items Menu items.
	 */
	public function w3tc_admin_bar_menu( $menu_items ) {
		$menu_items['20110.pagecache'] = array(
			'id'     => 'w3tc_flush_pgcache',
			'parent' => 'w3tc_flush',
			'title'  => __( 'Page Cache: All', 'w3-total-cache' ),
			'href'   => wp_nonce_url( admin_url( 'admin.php?page=w3tc_dashboard&amp;w3tc_flush_pgcache' ), 'w3tc' ),
		);

		if ( Util_Environment::detect_post_id() && ( ! defined( 'DOING_AJAX' ) || ! DOING_AJAX ) ) {
			$menu_items['20120.pagecache'] = array(
				'id'     => 'w3tc_pgcache_flush_post',
				'parent' => 'w3tc_flush',
				'title'  => __( 'Page Cache: Current Page', 'w3-total-cache' ),
				'href'   => wp_nonce_url(
					admin_url(
						'admin.php?page=w3tc_dashboard&amp;w3tc_flush_post&amp;post_id=' .
							Util_Environment::detect_post_id() . '&amp;force=true'
					),
					'w3tc'
				),
			);
		}

		return $menu_items;
	}

	/**
	 * Flush cache group.
	 *
	 * @param string $group Group name.
	 * @param array  $extras Additionals to flush.
	 */
	public function w3tc_flush_group( $group, $extras = array() ) {
		if ( isset( $extras['only'] ) && 'pagecache' !== (string) $extras['only'] ) {
			return;
		}

		$pgcacheflush = Dispatcher::component( 'PgCache_Flush' );
		$v            = $pgcacheflush->flush_group( $group );

		return $v;
	}

	/**
	 * Flushes all caches
	 *
	 * @param array $extras Additionals to flush.
	 *
	 * @return boolean
	 */
	public function w3tc_flush_posts( $extras = array() ) {
		if ( isset( $extras['only'] ) && 'pagecache' !== (string) $extras['only'] ) {
			return;
		}

		$pgcacheflush = Dispatcher::component( 'PgCache_Flush' );
		$v            = $pgcacheflush->flush();

		return $v;
	}

	/**
	 * Flushes post cache
	 *
	 * @param integer $post_id Post ID.
	 * @param boolean $force   Force flag (optional).
	 *
	 * @return boolean
	 */
	public function w3tc_flush_post( $post_id, $force = false ) {
		$pgcacheflush = Dispatcher::component( 'PgCache_Flush' );
		$v            = $pgcacheflush->flush_post( $post_id, $force );

		return $v;
	}

	/**
	 * Flushes post cache
	 *
	 * @param string $url URL.
	 *
	 * @return boolean
	 */
	public function w3tc_flush_url( $url ) {
		$pgcacheflush = Dispatcher::component( 'PgCache_Flush' );
		$v            = $pgcacheflush->flush_url( $url );

		return $v;
	}



	/**
	 * By default headers are not cached by file_generic
	 *
	 * @param mixed  $header New header.
	 * @param mixed  $header_original Original header.
	 * @param string $pagecache_engine Engine name.
	 *
	 * @return mixed|null
	 */
	public function w3tc_pagecache_set_header( $header, $header_original, $pagecache_engine ) {
		if ( 'file_generic' === (string) $pagecache_engine ) {
			return null;
		}

		return $header;
	}

	/**
	 * Save config item
	 *
	 * @param array $config Config.
	 */
	public function w3tc_config_save( $config ) {
		// frontend activity.
		if ( $config->get_boolean( 'pgcache.cache.feed' ) ) {
			$config->set( 'pgcache.cache.nginx_handle_xml', true );
		}
	}
}
