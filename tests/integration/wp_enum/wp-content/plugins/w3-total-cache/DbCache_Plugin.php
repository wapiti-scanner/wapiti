<?php
/**
 * File: DbCache_Plugin.php
 *
 * @package W3TC
 *
 * phpcs:disable PSR2.Classes.PropertyDeclaration.Underscore
 */

namespace W3TC;

/**
 * W3 DbCache plugin
 */
class DbCache_Plugin {
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
		// phpcs:ignore WordPress.WP.CronInterval.ChangeDetected
		add_filter( 'cron_schedules', array( $this, 'cron_schedules' ) );

		if ( 'file' === $this->_config->get_string( 'dbcache.engine' ) ) {
			add_action( 'w3_dbcache_cleanup', array( $this, 'cleanup' ) );
		}

		// Posts.
		add_action( 'publish_phone', array( $this, 'on_change' ), 0 );
		add_action( 'wp_trash_post', array( $this, 'on_post_change' ), 0 );
		add_action( 'save_post', array( $this, 'on_post_change' ), 0 );
		add_action( 'clean_post_cache', array( $this, 'on_post_change' ), 0, 2 );
		add_action( 'delete_post', array( $this, 'on_post_change' ), 0 );

		// Comments.
		add_action( 'comment_post', array( $this, 'on_comment_change' ), 0 );
		add_action( 'edit_comment', array( $this, 'on_comment_change' ), 0 );
		add_action( 'delete_comment', array( $this, 'on_comment_change' ), 0 );
		add_action( 'wp_set_comment_status', array( $this, 'on_comment_status' ), 0, 2 );
		add_action( 'trackback_post', array( $this, 'on_comment_change' ), 0 );
		add_action( 'pingback_post', array( $this, 'on_comment_change' ), 0 );

		// Theme.
		add_action( 'switch_theme', array( $this, 'on_change' ), 0 );

		// Profile.
		add_action( 'edit_user_profile_update', array( $this, 'on_change' ), 0 );

		if ( Util_Environment::is_wpmu() ) {
			add_action( 'delete_blog', array( $this, 'on_change' ), 0 );
		}

		add_filter( 'w3tc_admin_bar_menu', array( $this, 'w3tc_admin_bar_menu' ) );

		// usage statistics handling.
		add_filter( 'w3tc_usage_statistics_metrics', array( $this, 'w3tc_usage_statistics_metrics' ) );
		add_filter( 'w3tc_usage_statistics_sources', array( $this, 'w3tc_usage_statistics_sources' ) );
	}

	/**
	 * Does disk cache cleanup
	 *
	 * @return void
	 */
	public function cleanup() {
		$w3_cache_file_cleaner = new Cache_File_Cleaner(
			array(
				'cache_dir'       => Util_Environment::cache_blog_dir( 'db' ),
				'clean_timelimit' => $this->_config->get_integer( 'timelimit.cache_gc' ),
			)
		);

		$w3_cache_file_cleaner->clean();
	}

	/**
	 * Cron schedules filter
	 *
	 * @param array $schedules Schedules.
	 *
	 * @return array
	 */
	public function cron_schedules( $schedules ) {
		$gc = $this->_config->get_integer( 'dbcache.file.gc' );

		return array_merge(
			$schedules,
			array(
				'w3_dbcache_cleanup' => array(
					'interval' => $gc,
					'display'  => sprintf(
						// translators: 1 interval in seconds.
						__( '[W3TC] Database Cache file GC (every %d seconds)', 'w3-total-cache' ),
						$gc
					),
				),
			)
		);
	}

	/**
	 * Change action
	 */
	public function on_change() {
		static $flushed = false;

		if ( ! $flushed ) {
			$flusher = Dispatcher::component( 'CacheFlush' );
			$flusher->dbcache_flush();

			$flushed = true;
		}
	}

	/**
	 * Change post action
	 *
	 * @param int   $post_id Post ID.
	 * @param mixed $post Post.
	 */
	public function on_post_change( $post_id = 0, $post = null ) {
		static $flushed = false;

		if ( ! $flushed ) {
			if ( is_null( $post ) ) {
				$post = $post_id;
			}

			if ( $post_id > 0 && ! Util_Environment::is_flushable_post( $post, 'dbcache', $this->_config ) ) {
				return;
			}

			$flusher = Dispatcher::component( 'CacheFlush' );
			$flusher->dbcache_flush();

			$flushed = true;
		}
	}

	/**
	 * Comment change action
	 *
	 * @param integer $comment_id Comment ID.
	 */
	public function on_comment_change( $comment_id ) {
		$post_id = 0;

		if ( $comment_id ) {
			$comment = get_comment( $comment_id, ARRAY_A );
			$post_id = ! empty( $comment['comment_post_ID'] ) ? (int) $comment['comment_post_ID'] : 0;
		}

		$this->on_post_change( $post_id );
	}

	/**
	 * Comment status action fired immediately after transitioning a comment’s status from one to another
	 * in the database and removing the comment from the database cache, but prior to all status transition hooks.
	 *
	 * @link https://developer.wordpress.org/reference/functions/wp_set_comment_status/
	 *
	 * @param integer $comment_id Comment ID.
	 * @param string  $status Status.
	 */
	public function on_comment_status( $comment_id, $status ) {
		$this->on_comment_change( $comment_id );
	}

	/**
	 * Setup admin menu elements
	 *
	 * @param array $menu_items Menu items.
	 */
	public function w3tc_admin_bar_menu( $menu_items ) {
		$menu_items['20310.dbcache'] = array(
			'id'     => 'w3tc_flush_dbcache',
			'parent' => 'w3tc_flush',
			'title'  => __( 'Database', 'w3-total-cache' ),
			'href'   => wp_nonce_url(
				admin_url( 'admin.php?page=w3tc_dashboard&amp;w3tc_flush_dbcache' ),
				'w3tc'
			),
		);

		return $menu_items;
	}

	/**
	 * Usage statistics of request filter
	 *
	 * @param object $storage Storage object.
	 */
	public function w3tc_usage_statistics_of_request( $storage ) {
		$o = Dispatcher::component( 'ObjectCache_WpObjectCache_Regular' );
		$o->w3tc_usage_statistics_of_request( $storage );
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
				'dbcache_calls_total',
				'dbcache_calls_hits',
				'dbcache_flushes',
				'dbcache_time_ms',
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
		if ( 'apc' === $c->get_string( 'dbcache.engine' ) ) {
			$sources['apc_servers']['dbcache'] = array(
				'name' => __( 'Database Cache', 'w3-total-cache' ),
			);
		} elseif ( 'memcached' === $c->get_string( 'dbcache.engine' ) ) {
			$sources['memcached_servers']['dbcache'] = array(
				'servers'  => $c->get_array( 'dbcache.memcached.servers' ),
				'username' => $c->get_string( 'dbcache.memcached.username' ),
				'password' => $c->get_string( 'dbcache.memcached.password' ),
				'name'     => __( 'Database Cache', 'w3-total-cache' ),
			);
		} elseif ( 'redis' === $c->get_string( 'dbcache.engine' ) ) {
			$sources['redis_servers']['dbcache'] = array(
				'servers'                 => $c->get_array( 'dbcache.redis.servers' ),
				'verify_tls_certificates' => $c->get_boolean( 'dbcache.redis.verify_tls_certificates' ),
				'username'                => $c->get_boolean( 'dbcache.redis.username' ),
				'dbid'                    => $c->get_integer( 'dbcache.redis.dbid' ),
				'password'                => $c->get_string( 'dbcache.redis.password' ),
				'name'                    => __( 'Database Cache', 'w3-total-cache' ),
			);
		}

		return $sources;
	}
}
