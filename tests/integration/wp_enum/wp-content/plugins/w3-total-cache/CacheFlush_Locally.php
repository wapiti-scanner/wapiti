<?php
namespace W3TC;

/**
 * W3 Cache flushing
 *
 * priorities are very important for actions here.
 * if e.g. CDN is flushed before local page cache - CDN can cache again
 * still not flushed pages from local page cache.
 *  100 - db
 *  200 - 999 local objects, like object cache
 *  1000 - 1999 local files (minify, pagecache)
 *  2000 - 2999 local reverse proxies varnish, nginx
 *  3000 -  external caches like cdn, cloudflare
 */
class CacheFlush_Locally {
	/**
	 * Cleans db cache
	 */
	function dbcache_flush( $extras = array() ) {
		if ( isset( $extras['only'] ) && $extras['only'] != 'dbcache' )
			return;

		do_action( 'w3tc_flush_dbcache' );

		if ( !method_exists( $GLOBALS['wpdb'], 'flush_cache' ) )
			return false;

		return $GLOBALS['wpdb']->flush_cache( $extras );
	}

	/**
	 * Cleans object cache
	 */
	function objectcache_flush( $extras = array() ) {
		if ( isset( $extras['only'] ) && $extras['only'] != 'objectcache' )
			return;

		do_action( 'w3tc_flush_objectcache' );
		$objectcache = Dispatcher::component( 'ObjectCache_WpObjectCache_Regular' );
		$v = $objectcache->flush();

		do_action( 'w3tc_flush_after_objectcache' );

		return $v;
	}

	/**
	 * Cleans fragment cache
	 */
	function fragmentcache_flush( $extras = array() ) {
		if ( isset( $extras['only'] ) && $extras['only'] != 'fragment' )
			return;

		do_action( 'w3tc_flush_fragmentcache' );
		do_action( 'w3tc_flush_after_fragmentcache' );

		return true;
	}

	/**
	 * Cleans fragment cache
	 */
	function fragmentcache_flush_group( $group ) {
		do_action( 'w3tc_flush_fragmentcache_group', $group );
		do_action( 'w3tc_flush_after_fragmentcache_group', $group );

		return true;
	}

	function minifycache_flush( $extras = array() ) {
		if ( isset( $extras['only'] ) && $extras['only'] != 'minify' )
			return;

		do_action( 'w3tc_flush_minify' );
		$minifycache = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );
		$v = $minifycache->flush();
		do_action( 'w3tc_flush_after_minify' );

		return $v;
	}

	function minifycache_flush_all( $extras = array() ) {
		if ( isset( $extras['minify'] ) && $extras['minify'] == 'purge_map' )
			delete_option( 'w3tc_minify' );

		$this->minifycache_flush( $extras );
	}

	/**
	 * Updates Query String
	 */
	function browsercache_flush( $extras = array() ) {
		if ( isset( $extras['only'] ) && $extras['only'] != 'browsercache' )
			return;

		do_action( 'w3tc_flush_browsercache' );
		update_option( 'w3tc_browsercache_flush_timestamp',
			rand( 10000, 99999 ) . '' );
		do_action( 'w3tc_flush_after_browsercache' );
	}

	/**
	 * Purge CDN mirror cache
	 */
	function cdn_purge_all( $extras = array() ) {
		$do_flush = apply_filters( 'w3tc_preflush_cdn_all', true, $extras );

		$v = false;
		if ( $do_flush ) {
			do_action( 'w3tc_cdn_purge_all' );
			$cdn_core = Dispatcher::component( 'Cdn_Core' );
			$cdn = $cdn_core->get_cdn();
			$results = array();
			$v = $cdn->purge_all( $results );
			do_action( 'w3tc_cdn_purge_all_after' );
		}

		return $v;
	}

	/**
	 * Purges Files from Varnish (If enabled) and CDN
	 *
	 * @param array   $purgefiles array consisting of CdnCommon file descriptors
	 *                          array(array('local_path'=>'', 'remote_path'=> ''))
	 * @return boolean
	 */
	function cdn_purge_files( $purgefiles ) {
		do_action( 'w3tc_cdn_purge_files', $purgefiles );
		$common = Dispatcher::component( 'Cdn_Core' );
		$results = array();
		$v = $common->purge( $purgefiles, $results );
		do_action( 'w3tc_cdn_purge_files_after', $purgefiles );

		return $v;
	}


	/**
	 * Flushes the system APC
	 *
	 * @return bool
	 */
	function opcache_flush() {
		$o = Dispatcher::component( 'SystemOpCache_Core' );
		return $o->flush();
	}

	/**
	 * Purges/Flushes post from page cache, varnish and cdn cache
	 *
	 * @param integer $post_id Post ID.
	 * @param boolean $force   Force flag (optional).
	 * @param array   $extras  Extras.
	 */
	function flush_post( $post_id, $force = false, $extras = null ) {
		$do_flush = apply_filters( 'w3tc_preflush_post', true, $extras );
		if ( $do_flush )
			do_action( 'w3tc_flush_post', $post_id, $force, $extras );
	}

	/**
	 * Purges/Flushes page contents - page cache, varnish and cdn cache
	 * When global changes affect whole content but not internal data structures
	 */
	function flush_posts( $extras = null ) {
		$do_flush = apply_filters( 'w3tc_preflush_posts', true, $extras );
		if ( $do_flush )
			do_action( 'w3tc_flush_posts', $extras );
	}

	/**
	 * Flushes all enabled caches.
	 */
	function flush_all( $extras ) {
		static $default_actions_added = false;
		if ( !$default_actions_added ) {
			$config = Dispatcher::config();

			$opcache = Dispatcher::component( 'SystemOpCache_Core' );
			if ( $opcache->is_enabled() )
				add_action( 'w3tc_flush_all',
					array( $this, 'opcache_flush' ),
					50, 1 );

			if ( $config->get_boolean( 'dbcache.enabled' ) )
				add_action( 'w3tc_flush_all',
					array( $this, 'dbcache_flush' ),
					100, 2 );
			if ( $config->get_boolean( 'objectcache.enabled' ) )
				add_action( 'w3tc_flush_all',
					array( $this, 'objectcache_flush' ),
					200, 1 );
			if ( $config->get_boolean( 'minify.enabled' ) )
				add_action( 'w3tc_flush_all',
					array( $this, 'minifycache_flush_all' ),
					1000, 1 );

			$default_actions_added = true;
		}

		$do_flush = apply_filters( 'w3tc_preflush_all', true, $extras );
		if ( $do_flush )
			do_action( 'w3tc_flush_all', $extras );
	}

	function flush_group( $group, $extras ) {
		$do_flush = apply_filters( 'w3tc_preflush_group', true, $group, $extras );
		if ( $do_flush )
			do_action( 'w3tc_flush_group', $group, $extras );
	}

	/**
	 * Purges/Flushes url from page cache, varnish and cdn cache
	 */
	function flush_url( $url, $extras = null ) {
		$do_flush = apply_filters( 'w3tc_preflush_url', true, $extras );
		if ( $do_flush )
			do_action( 'w3tc_flush_url', $url, $extras );
	}

	/**
	 * Makes get request to url specific to post, ie permalinks
	 *
	 * @param unknown $post_id
	 * @return mixed
	 */
	function prime_post( $post_id ) {
		$pgcache = Dispatcher::component( 'PgCache_Plugin_Admin' );
		return $pgcache->prime_post( $post_id );
	}

	/**
	 * Called at the end of http request processing
	 * so that flushers can finish something they've decided to delay
	 */
	public function execute_delayed_operations() {
		static $default_actions_added = false;
		if ( !$default_actions_added ) {
			$config = Dispatcher::config();

			if ( $config->get_boolean( 'pgcache.enabled' ) )
				add_filter( 'w3tc_flush_execute_delayed_operations',
					array( $this, '_execute_delayed_operations_pgcache' ),
					1100 );
			if ( $config->get_boolean( 'varnish.enabled' ) )
				add_filter( 'w3tc_flush_execute_delayed_operations',
					array( $this, '_execute_delayed_operations_varnish' ),
					2000 );
			$default_actions_added = true;
		}

		// build response in a form 'module' => 'error message' (empty if no error)
		$actions_made = array();
		$actions_made = apply_filters( 'w3tc_flush_execute_delayed_operations',
			$actions_made );

		return $actions_made;
	}

	public function _execute_delayed_operations_pgcache( $actions_made ) {
		$o = Dispatcher::component( 'PgCache_Flush' );
		$count_flushed = $o->flush_post_cleanup();
		if ( $count_flushed > 0 )
			$actions_made[] = array( 'module' => 'pgcache' );

		return $actions_made;
	}

	public function _execute_delayed_operations_varnish( $actions_made ) {
		$o = Dispatcher::component( 'Varnish_Flush' );
		$count_flushed = $o->flush_post_cleanup();
		if ( $count_flushed > 0 )
			$actions_made[] = array( 'module' => 'varnish' );

		return $actions_made;
	}
}
