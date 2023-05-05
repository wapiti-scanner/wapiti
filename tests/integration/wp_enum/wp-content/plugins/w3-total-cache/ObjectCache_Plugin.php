<?php
/**
 * File: ObjectCache_Plugin.php
 *
 * @package W3TC
 *
 * phpcs:disable PSR2.Classes.PropertyDeclaration.Underscore
 */

namespace W3TC;

/**
 * W3 ObjectCache plugin
 */
class ObjectCache_Plugin {
	/**
	 * Config.
	 *
	 * @var array
	 */
	private $_config = null;

	/**
	 * If the object cache has been flushed.
	 *
	 * @since 2.2.10
	 *
	 * @var boolean
	 */
	private static $flushed = false;

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

		add_filter( 'w3tc_footer_comment', array( $this, 'w3tc_footer_comment' ) );

		if ( 'file' === $this->_config->get_string( 'objectcache.engine' ) ) {
			add_action( 'w3_objectcache_cleanup', array( $this, 'cleanup' ) );
		}

		add_action( 'save_post', array( $this, 'on_post_change' ), 0, 2 );
		add_action( 'delete_post', array( $this, 'on_post_change' ), 0, 2 );

		add_action( 'comment_post', array( $this, 'on_comment_change' ), 0 );
		add_action( 'edit_comment', array( $this, 'on_comment_change' ), 0 );
		add_action( 'delete_comment', array( $this, 'on_comment_change' ), 0 );
		add_action( 'wp_set_comment_status', array( $this, 'on_comment_status' ), 0, 2 );
		add_action( 'trackback_post', array( $this, 'on_comment_change' ), 0 );
		add_action( 'pingback_post', array( $this, 'on_comment_change' ), 0 );

		add_action( 'switch_theme', array( $this, 'on_change' ), 0 );

		add_action( 'updated_option', array( $this, 'on_change_option' ), 0, 1 );
		add_action( 'added_option', array( $this, 'on_change_option' ), 0, 1 );
		add_action( 'delete_option', array( $this, 'on_change_option' ), 0, 1 );

		add_action( 'edit_user_profile_update', array( $this, 'on_change_profile' ), 0 );

		add_filter( 'w3tc_admin_bar_menu', array( $this, 'w3tc_admin_bar_menu' ) );

		// usage statistics handling.
		add_action( 'w3tc_usage_statistics_of_request', array( $this, 'w3tc_usage_statistics_of_request' ), 10, 1 );
		add_filter( 'w3tc_usage_statistics_metrics', array( $this, 'w3tc_usage_statistics_metrics' ) );
		add_filter( 'w3tc_usage_statistics_sources', array( $this, 'w3tc_usage_statistics_sources' ) );

		if ( Util_Environment::is_wpmu() ) {
			add_action( 'delete_blog', array( $this, 'on_change' ), 0 );
			add_action( 'switch_blog', array( $this, 'switch_blog' ), 0, 2 );
		}
	}

	/**
	 * Does disk cache cleanup
	 *
	 * @return void
	 */
	public function cleanup() {
		$w3_cache_file_cleaner = new Cache_File_Cleaner(
			array(
				'cache_dir'       => Util_Environment::cache_blog_dir( 'object' ),
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
		$gc = $this->_config->get_integer( 'objectcache.file.gc' );

		return array_merge(
			$schedules,
			array(
				'w3_objectcache_cleanup' => array(
					'interval' => $gc,
					'display'  => sprintf(
						// translators: 1 interval in seconds.
						__( '[W3TC] Object Cache file GC (every %d seconds)', 'w3-total-cache' ),
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
		if ( ! self::$flushed ) {
			$flush = Dispatcher::component( 'CacheFlush' );
			$flush->objectcache_flush();
			self::$flushed = true;
		}
	}

	/**
	 * Change post action
	 *
	 * @param integer $post_id Post ID.
	 * @param mixed   $post Post.
	 */
	public function on_post_change( $post_id = 0, $post = null ) {
		if ( ! self::$flushed ) {
			if ( is_null( $post ) ) {
				$post = $post_id;
			}

			if ( $post_id > 0 && ! Util_Environment::is_flushable_post( $post, 'objectcache', $this->_config ) ) {
				return;
			}

			$flush = Dispatcher::component( 'CacheFlush' );
			$flush->objectcache_flush();
			self::$flushed = true;
		}
	}

	/**
	 * Change action
	 *
	 * @param string $option Option key.
	 */
	public function on_change_option( $option ) {
		if ( 'cron' === $option ) {
			wp_cache_delete( $option );
		}

		$do_flush = defined( 'WP_ADMIN' )
			|| $this->_config->get_boolean( 'cluster.messagebus.enabled' )
			|| $this->_config->get_boolean( 'objectcache.purge.all' );

		if ( ! self::$flushed && $do_flush ) {
			$flush = Dispatcher::component( 'CacheFlush' );
			$flush->objectcache_flush();
			self::$flushed = true;
		}
	}

	/**
	 * Flush cache when user profile is updated
	 *
	 * @param integer $user_id User ID.
	 */
	public function on_change_profile( $user_id ) {
		if ( ! self::$flushed ) {
			if ( Util_Environment::is_wpmu() ) {
				$blogs = get_blogs_of_user( $user_id, true );
				if ( $blogs ) {
					global $w3_multisite_blogs;
					$w3_multisite_blogs = $blogs;
				}
			}

			$flush = Dispatcher::component( 'CacheFlush' );
			$flush->objectcache_flush();

			self::$flushed = true;
		}
	}

	/**
	 * Switch blog action
	 *
	 * @param integer $blog_id Blog ID.
	 * @param integer $previous_blog_id Previous Blog ID.
	 */
	public function switch_blog( $blog_id, $previous_blog_id ) {
		$o = Dispatcher::component( 'ObjectCache_WpObjectCache_Regular' );
		$o->switch_blog( $blog_id );
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
			$post_id = ( ! empty( $comment['comment_post_ID'] ) ? (int) $comment['comment_post_ID'] : 0 );
		}

		$this->on_post_change( $post_id );
	}

	/**
	 * Comment status action fired immediately after transitioning a comment’s status from one to another
	 * in the database and removing the comment from the object cache, but prior to all status transition hooks.
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
		$menu_items['20410.objectcache'] = array(
			'id'     => 'w3tc_flush_objectcache',
			'parent' => 'w3tc_flush',
			'title'  => __( 'Object Cache', 'w3-total-cache' ),
			'href'   => wp_nonce_url( admin_url( 'admin.php?page=w3tc_dashboard&amp;w3tc_flush_objectcache' ), 'w3tc' ),
		);

		return $menu_items;
	}

	/**
	 * Setup admin menu elements
	 *
	 * @param array $strings Strings.
	 */
	public function w3tc_footer_comment( $strings ) {
		$o       = Dispatcher::component( 'ObjectCache_WpObjectCache_Regular' );
		$strings = $o->w3tc_footer_comment( $strings );

		return $strings;
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
		$metrics = array_merge(
			$metrics,
			array(
				'objectcache_get_total',
				'objectcache_get_hits',
				'objectcache_sets',
				'objectcache_flushes',
				'objectcache_time_ms',
			)
		);

		return $metrics;
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
		if ( 'apc' === $c->get_string( 'objectcache.engine' ) ) {
			$sources['apc_servers']['objectcache'] = array(
				'name' => __( 'Object Cache', 'w3-total-cache' ),
			);
		} elseif ( 'memcached' === $c->get_string( 'objectcache.engine' ) ) {
			$sources['memcached_servers']['objectcache'] = array(
				'servers'         => $c->get_array( 'objectcache.memcached.servers' ),
				'username'        => $c->get_string( 'objectcache.memcached.username' ),
				'password'        => $c->get_string( 'objectcache.memcached.password' ),
				'binary_protocol' => $c->get_boolean( 'objectcache.memcached.binary_protocol' ),
				'name'            => __( 'Object Cache', 'w3-total-cache' ),
			);
		} elseif ( 'redis' === $c->get_string( 'objectcache.engine' ) ) {
			$sources['redis_servers']['objectcache'] = array(
				'servers'                 => $c->get_array( 'objectcache.redis.servers' ),
				'verify_tls_certificates' => $c->get_boolean( 'objectcache.redis.verify_tls_certificates' ),
				'username'                => $c->get_boolean( 'objectcache.redis.username' ),
				'dbid'                    => $c->get_integer( 'objectcache.redis.dbid' ),
				'password'                => $c->get_string( 'objectcache.redis.password' ),
				'name'                    => __( 'Object Cache', 'w3-total-cache' ),
			);
		}

		return $sources;
	}
}
