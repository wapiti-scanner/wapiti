<?php
namespace W3TC;



class Generic_AdminActions_Flush {
	private $_config = null;

	function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Flush all caches action
	 *
	 * @return void
	 */
	function w3tc_flush_all() {
		w3tc_flush_all( array( 'ui_action' => 'flush_button' ) );
		$this->_redirect_after_flush( 'flush_all' );
	}

	function w3tc_flush_current_page() {
		$url = filter_input( INPUT_GET, 'url', FILTER_SANITIZE_URL );
		if ( empty( $url ) && isset( $_SERVER['HTTP_REFERER'] ) ) {
			$url = sanitize_text_field( wp_unslash( $_SERVER['HTTP_REFERER'] ) );
		}
		w3tc_flush_url( $url );

		?>
		<div style="text-align: center; margin-top: 30px">
		<h3>Page has been flushed successfully</h3>
		<a id="w3tc_return" href="<?php echo esc_attr( $url ) ?>">Return</a>
		</div>
		<script>
		setTimeout(function() {
			window.location = document.getElementById('w3tc_return').href;
		}, 2000);
		</script>
		<?php
		exit();
	}

	/**
	 * Flush memcache cache action
	 *
	 * @return void
	 */
	function w3tc_flush_memcached() {
		$this->flush_memcached();

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_memcached'
			), true );
	}

	/**
	 * Flush opcode caches action
	 *
	 * @return void
	 */
	function w3tc_flush_opcode() {
		$this->flush_opcode();

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_opcode'
			), true );
	}

	/**
	 * Flush file caches action
	 *
	 * @return void
	 */
	function w3tc_flush_file() {
		$this->flush_file();

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_file'
			), true );
	}

	/**
	 * Flush from static files and further
	 *
	 * @return void
	 */
	function w3tc_flush_statics() {
		$cf = Dispatcher::component( 'CacheFlush' );
		$cf->browsercache_flush();
		w3tc_flush_posts();

		$state_note = Dispatcher::config_state_note();
		$state_note->set( 'common.show_note.flush_statics_needed', false );
		$state_note->set( 'common.show_note.flush_posts_needed', false );
		$state_note->set( 'common.show_note.plugins_updated', false );

		Util_Admin::redirect_with_custom_messages2( array(
				'notes' => array(
					__( 'Static files cache successfully emptied.', 'w3-total-cache' )
				)
			), true );
	}

	/**
	 * Flush posts
	 *
	 * @return void
	 */
	function w3tc_flush_posts() {
		w3tc_flush_posts();

		$state_note = Dispatcher::config_state_note();
		$state_note->set( 'common.show_note.flush_posts_needed', false );
		$state_note->set( 'common.show_note.plugins_updated', false );

		$this->_redirect_after_flush( 'flush_pgcache' );
	}

	/**
	 * Flush page cache action
	 *
	 * @return void
	 */
	function w3tc_flush_pgcache() {
		w3tc_flush_posts( array( 'ui_action' => 'flush_button' ) );

		$state_note = Dispatcher::config_state_note();
		$state_note->set( 'common.show_note.flush_posts_needed', false );
		$state_note->set( 'common.show_note.plugins_updated', false );

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_pgcache'
			), true );
	}

	/**
	 * Flush database cache action
	 *
	 * @return void
	 */
	function w3tc_flush_dbcache() {
		$this->flush_dbcache();

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_dbcache'
			), true );
	}

	/**
	 * Flush object cache action
	 *
	 * @return void
	 */
	function w3tc_flush_objectcache() {
		$this->flush_objectcache();

		$state_note = Dispatcher::config_state_note();
		$state_note->set( 'objectcache.show_note.flush_needed', false );

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_objectcache'
			), true );
	}


	/**
	 * Flush fragment cache action
	 *
	 * @return void
	 */
	function w3tc_flush_fragmentcache() {
		$this->flush_fragmentcache();

		$this->_config->set( 'notes.need_empty_fragmentcache', false );

		$this->_config->save();

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_fragmentcache'
			), true );
	}

	/**
	 * Flush minify action
	 *
	 * @return void
	 */
	function w3tc_flush_minify() {
		$this->flush_minify();

		$state_note = Dispatcher::config_state_note();
		$state_note->set( 'minify.show_note.need_flush', false );

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_minify'
			), true );
	}

	/**
	 * Flush browser cache action
	 *
	 * @return void
	 */
	function w3tc_flush_browser_cache() {
		$cacheflush = Dispatcher::component( 'CacheFlush' );
		$cacheflush->browsercache_flush();

		$state_note = Dispatcher::config_state_note();
		$state_note->set( 'common.show_note.flush_statics_needed', false );
		$state_note->set( 'common.show_note.flush_posts_needed', true );

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_browser_cache'
			), true );
	}

	/*
	 * Flush varnish cache
	 */
	function w3tc_flush_varnish() {
		$this->flush_varnish();

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_varnish'
			), true );
	}

	/*
	 * Flush CDN mirror
	 */
	function w3tc_flush_cdn() {
		$this->flush_cdn( array( 'ui_action' => 'flush_button' ) );

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_cdn'
			), true );
	}


	/**
	 * PgCache purge post
	 *
	 * @return void
	 */
	function w3tc_flush_post() {
		$post_id = Util_Request::get_integer( 'post_id' );
		w3tc_flush_post( $post_id, true, array( 'ui_action' => 'flush_button' ) );

		Util_Admin::redirect( array(
				'w3tc_note' => 'pgcache_purge_post'
			), true );
	}

	/**
	 * Flush specified cache
	 *
	 * @param string  $type
	 * @return void
	 */
	function flush( $type ) {
		$state = Dispatcher::config_state();
		$state_note = Dispatcher::config_state_note();

		if ( $this->_config->get_string( 'pgcache.engine' ) == $type && $this->_config->get_boolean( 'pgcache.enabled' ) ) {
			$state_note->set( 'common.show_note.flush_posts_needed', false );
			$state_note->set( 'common.show_note.plugins_updated', false );

			$pgcacheflush = Dispatcher::component( 'PgCache_Flush' );
			$pgcacheflush->flush();
			$pgcacheflush->flush_post_cleanup();
		}

		if ( $this->_config->get_string( 'dbcache.engine' ) == $type && $this->_config->get_boolean( 'dbcache.enabled' ) ) {
			$this->flush_dbcache();
		}

		if ( $this->_config->get_string( 'objectcache.engine' ) == $type && $this->_config->get_boolean( 'objectcache.enabled' ) ) {
			$this->flush_objectcache();
		}

		if ( $this->_config->get_string( array( 'fragmentcache', 'engine' ) ) == $type ) {
			$this->flush_fragmentcache();
		}

		if ( $this->_config->get_string( 'minify.engine' ) == $type && $this->_config->get_boolean( 'minify.enabled' ) ) {
			$state_note->set( 'minify.show_note.need_flush', false );
			$this->flush_minify();
		}
	}

	/**
	 * Flush memcached cache
	 *
	 * @return void
	 */
	function flush_memcached() {
		$this->flush( 'memcached' );
	}

	/**
	 * Flush APC cache
	 *
	 * @return void
	 */
	function flush_opcode() {
		$cacheflush = Dispatcher::component( 'CacheFlush' );
		$cacheflush->opcache_flush();
	}

	/**
	 * Flush file cache
	 *
	 * @return void
	 */
	function flush_file() {
		$this->flush( 'file' );
		$this->flush( 'file_generic' );
	}

	/**
	 * Flush database cache
	 *
	 * @return void
	 */
	function flush_dbcache() {
		$flusher = Dispatcher::component( 'CacheFlush' );
		$flusher->dbcache_flush();
	}

	/**
	 * Flush object cache
	 *
	 * @return void
	 */
	function flush_objectcache() {
		$flusher = Dispatcher::component( 'CacheFlush' );
		$flusher->objectcache_flush();
	}

	/**
	 * Flush fragment cache
	 */
	function flush_fragmentcache() {
		$flusher = Dispatcher::component( 'CacheFlush' );
		$flusher->fragmentcache_flush();
	}

	/**
	 * Flush minify cache
	 *
	 * @return void
	 */
	function flush_minify() {
		$w3_minify = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );
		$w3_minify->flush();
	}

	/**
	 * Flush varnish cache
	 */
	function flush_varnish() {
		// this attaches execute_delayed_operations! otherwise
		// specific module flush will not have effect
		$cacheflush = Dispatcher::component( 'CacheFlush' );

		$varnishflush = Dispatcher::component( 'Varnish_Flush' );
		$varnishflush->flush();
	}

	/**
	 * Flush CDN mirror
	 */
	function flush_cdn( $extras = array() ) {
		$cacheflush = Dispatcher::component( 'CacheFlush' );
		$cacheflush->cdn_purge_all( $extras );
	}


	private function _redirect_after_flush( $success_note ) {
		$flush = Dispatcher::component( 'CacheFlush' );
		$status = $flush->execute_delayed_operations();

		$errors = array();
		foreach ( $status as $i ) {
			if ( isset( $i['error'] ) )
				$errors[] = $i['error'];
		}

		if ( empty( $errors ) ) {
			Util_Admin::redirect( array(
					'w3tc_note' => $success_note
				), true );
		} else {
			Util_Admin::redirect_with_custom_messages2( array(
					'errors' => array( 'Failed to purge: ' .
						implode( ', ', $errors ) )
				), true );
		}
	}
}
