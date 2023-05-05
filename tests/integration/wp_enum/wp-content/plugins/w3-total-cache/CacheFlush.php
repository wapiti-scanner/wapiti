<?php
namespace W3TC;

/**
 * W3 Cache flushing
 */
class CacheFlush {
	private $_config;
	private $_executor;

	/**
	 * PHP5 Constructor
	 */
	function __construct() {
		$this->_config = Dispatcher::config();
		$sns = $this->_config->get_boolean( 'cluster.messagebus.enabled' );

		if ( $sns )
			$this->_executor = new Enterprise_CacheFlush_MakeSnsEvent();
		else
			$this->_executor = new CacheFlush_Locally();

		if ( function_exists( 'add_action' ) ) {
			add_action( 'w3tc_redirect', array(
					$this,
					'execute_delayed_operations'
				), 100000, 0 );
			add_filter( 'wp_redirect', array(
					$this,
					'execute_delayed_operations_filter'
				), 100000, 1 );
			add_action( 'w3tc_messagebus_message_processed', array(
					$this,
					'execute_delayed_operations'
				), 0 );
			add_action( 'shutdown', array(
					$this,
					'execute_delayed_operations'
				), 100000, 0 );
		}
	}

	/**
	 * Flushes database cache
	 */
	function dbcache_flush() {
		if ( $this->_config->get_boolean( 'dbcache.enabled' ) ) {
			$this->_executor->dbcache_flush();
		}
	}

	/**
	 * Flushes minify cache
	 */
	function minifycache_flush() {
		if ( $this->_config->get_boolean( 'minify.enabled' ) ) {
			$this->_executor->minifycache_flush();
		}
	}

	/**
	 * Flushes object cache
	 */
	function objectcache_flush() {
		if ( $this->_config->get_boolean( 'objectcache.enabled' ) ) {
			$this->_executor->objectcache_flush();
		}
	}

	/**
	 * Flushes fragment cache
	 */
	function fragmentcache_flush() {
		$this->_executor->fragmentcache_flush();
	}


	/**
	 * Flushes fragment cache based on group
	 */
	function fragmentcache_flush_group( $group ) {
		$this->_executor->fragmentcache_flush_group( $group );
	}

	/**
	 * Updates Browser Query String
	 */
	function browsercache_flush() {
		if ( $this->_config->get_boolean( 'browsercache.enabled' ) ) {
			$this->_executor->browsercache_flush();
		}
	}

	/**
	 * Purge CDN mirror cache
	 */
	function cdn_purge_all( $extras = array() ) {
		if ( $this->_config->get_boolean( 'cdn.enabled' ) )
			return $this->_executor->cdn_purge_all( $extras );

		return false;
	}

	/**
	 * Purges CDN files
	 */
	function cdn_purge_files( $purgefiles ) {
		$this->_executor->cdn_purge_files( $purgefiles );
	}

	/**
	 * Clears the system APC
	 *
	 * @return mixed
	 */
	function opcache_flush() {
		return $this->_executor->opcache_flush();
	}

	/**
	 * Purges/Flushes post page
	 */
	function flush_post( $post_id, $extras = null ) {
		return $this->_executor->flush_post( $post_id, $extras );
	}

	/**
	 * Checks if page contents can be flushed (i.e. cached at all)
	 */
	function flushable_posts( $extras = null ) {
		$flushable_posts = apply_filters( 'w3tc_flushable_posts', false,
			$extras );
		return $flushable_posts;
	}

	/**
	 * Purges/Flushes all posts
	 */
	function flush_posts( $extras = null ) {
		return $this->_executor->flush_posts( $extras );
	}

	/**
	 * Purges/Flushes all enabled caches
	 */
	function flush_all( $extras = null ) {
		static $flushed = false;
		if ( !$flushed ) {
			$flushed = true;
			$this->_executor->flush_all( $extras );
		}
	}

	/**
	 * Purges/Flushes cache group
	 */
	function flush_group( $group, $extras = null ) {
		static $flushed_groups = array();
		if ( !isset( $flushed_groups[$group] ) ) {
			$flushed_groups[$group] = '*';
			$this->_executor->flush_group( $group, $extras );
		}
	}

	/**
	 * Purges/Flushes url
	 */
	function flush_url( $url, $extras = null ) {
		static $flushed_urls = array();

		if ( !in_array( $url, $flushed_urls ) ) {
			$flushed_urls[] = $url;
			return $this->_executor->flush_url( $url, $extras );
		}
		return true;
	}

	/**
	 * Makes get request to url specific to post, ie permalinks
	 *
	 * @param unknown $post_id
	 * @return boolean
	 */
	function prime_post( $post_id ) {
		return $this->_executor->prime_post( $post_id );
	}



	function execute_delayed_operations() {
		return $this->_executor->execute_delayed_operations();
	}



	function execute_delayed_operations_filter( $v ) {
		$this->execute_delayed_operations();

		return $v;
	}
}
