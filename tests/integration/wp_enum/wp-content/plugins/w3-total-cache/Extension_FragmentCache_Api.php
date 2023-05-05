<?php

/*
 * @param string $fragment_group
 * @param boolean $global If group is for whole network in MS install
 * @return mixed
 */
function w3tc_fragmentcache_flush_group( $fragment_group ) {
	$o = \W3TC\Dispatcher::component( 'CacheFlush' );
	return $o->fragmentcache_flush_group( $fragment_group );
}

/**
 * Flush all fragment groups
 *
 * @return mixed
 */
function w3tc_fragmentcache_flush() {
	$o = \W3TC\Dispatcher::component( 'CacheFlush' );
	return $o->fragmentcache_flush();
}

/**
 * Register a fragment group and connected actions for current blog
 *
 * @param string  $group
 * @param array   $actions    on which actions group should be flushed
 * @param integer $expiration in seconds
 * @return mixed
 */
function w3tc_register_fragment_group( $group, $actions, $expiration ) {
	if ( !is_int( $expiration ) ) {
		$expiration = (int) $expiration;
		trigger_error( __FUNCTION__ . ' needs expiration parameter to be an int.', E_USER_WARNING );
	}
	$o = \W3TC\Dispatcher::component( 'Extension_FragmentCache_Core' );
	return $o->register_group( $group, $actions, $expiration );
}

/**
 * Register a fragment group for whole network in MS install
 *
 * @param unknown $group
 * @param unknown $actions
 * @param integer $expiration in seconds
 * @return mixed
 */
function w3tc_register_fragment_global_group( $group, $actions, $expiration ) {
	if ( !is_int( $expiration ) ) {
		$expiration = (int) $expiration;
		trigger_error( __FUNCTION__ . ' needs expiration parameter to be an int.', E_USER_WARNING );
	}
	$o = \W3TC\Dispatcher::component( 'Extension_FragmentCache_Core' );
	return $o->register_global_group( $group, $actions,
		$expiration );
}

/**
 * Starts caching output
 *
 * @param string  $id    the fragment id
 * @param string  $group the fragment group name.
 * @param string  $hook  name of the action/filter hook to disable on fragment found
 * @return bool returns true if cached fragment is echoed
 */
function w3tc_fragmentcache_start( $id, $group = '', $hook = '' ) {
	$fragment = w3tc_fragmentcache_get( $id, $group );
	if ( false === $fragment ) {
		_w3tc_caching_fragment( $id, $group );
		ob_start();
	} else {
		echo esc_html( $fragment );
		if ( $hook ) {
			remove_all_filters($hook);
		}
		return true;
	}
	return false;
}

/**
 * Starts caching filter, returns if filter already cached.
 *
 * @param string  $id    the fragment id
 * @param string  $group the fragment group name.
 * @param string  $hook  name of the action/filter hook to disable on fragment found
 * @param mixed   $data  the data returned by the filter
 * @return mixed
 */
function w3tc_fragmentcache_filter_start( $id, $group = '', $hook = '', $data = null ) {
	_w3tc_caching_fragment( $id, $group );
	$fragment = w3tc_fragmentcache_get( $id, $group );
	if ( false !== $fragment ) {
		if ( $hook ) {
			remove_all_filters($hook);
		}
		return $fragment;
	}
	return  $data;
}

/**
 * Ends the caching of output. Stores it and outputs the content
 *
 * @param string  $id    the fragment id
 * @param string  $group the fragment group
 * @param bool    $debug
 */
function w3tc_fragmentcache_end( $id, $group = '', $debug = false ) {
	if ( w3tc_is_caching_fragment( $id, $group ) ) {
		$content = ob_get_contents();
		if ( $debug )
			$content = sprintf( "\r\n".'<!-- fragment start (%s%s)-->'."\r\n".'%s'."\r\n".'<!-- fragment end (%1$s%2$s) cached at %s by W3 Total Cache expires in %d seconds -->'."\r\n", $group, $id, $content, date_i18n( 'Y-m-d H:i:s' ), 1000 );
		w3tc_fragmentcache_store( $id, $group, $content );
		ob_end_flush();
	}
}


/**
 * Ends the caching of filter. Stores it and returns the content
 *
 * @param string  $id    the fragment id
 * @param string  $group the fragment group
 * @param mixed   $data
 * @return mixed
 */
function w3tc_fragmentcache_filter_end( $id, $group = '', $data = null ) {
	if ( w3tc_is_caching_fragment( $id, $group ) ) {
		w3tc_fragmentcache_store( $id, $group, $data );
	}
	return $data;
}

/**
 * Stores an fragment
 *
 * @param unknown $id
 * @param string  $group
 * @param string  $content
 */
function w3tc_fragmentcache_store( $id, $group = '', $content = '' ) {
	set_transient( "{$group}{$id}", $content,
		1000 /* default expiration in a case its not catched by fc plugin */ );
}

/**
 *
 *
 * @param unknown $id
 * @param string  $group
 * @return object
 */
function w3tc_fragmentcache_get( $id, $group = '' ) {
	return get_transient( "{$group}{$id}" );
}

/**
 * Flushes a fragment from the cache
 *
 * @param unknown $id
 * @param string  $group
 */
function w3tc_fragmentcache_flush_fragment( $id, $group = '' ) {
	delete_transient( "{$group}{$id}" );
}

/**
 * Checks wether page fragment caching is being done for the item
 *
 * @param string  $id    fragment id
 * @param string  $group which group fragment belongs too
 * @return bool
 */
function w3tc_is_caching_fragment( $id, $group = '' ) {
	global $w3tc_caching_fragment;
	return isset( $w3tc_caching_fragment["{$group}{$id}"] ) &&
		$w3tc_caching_fragment["{$group}{$id}"];
}

/**
 * Internal function, sets if page fragment by $id and $group is being cached
 *
 * @param string  $id    fragment id
 * @param string  $group which group fragment belongs too
 */
function _w3tc_caching_fragment( $id, $group = '' ) {
	global $w3tc_caching_fragment;
	$w3tc_caching_fragment["{$group}{$id}"] = true;
}
