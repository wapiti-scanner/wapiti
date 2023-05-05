<?php
namespace W3TC;



class Extension_FragmentCache_Core {
	private $_fragment_groups = array();
	private $_actions = array();

	/**
	 * Register transients group
	 *
	 * @param unknown $group
	 * @param unknown $actions
	 * @param unknown $expiration
	 */
	function register_group( $group, $actions, $expiration ) {
		return $this->_register_group( $group, $actions, $expiration, false );
	}



	/**
	 * Register site-transients group
	 *
	 * @param string  $group
	 * @param array   $actions
	 * @param int     $expiration
	 */
	function register_global_group( $group, $actions, $expiration ) {
		return $this->_register_group( $group, $actions, $expiration, true );
	}



	private function _register_group( $group, $actions, $expiration, $global ) {
		if ( empty( $group ) )
			return;

		if ( !is_int( $expiration ) ) {
			$expiration = (int) $expiration;
			trigger_error( __METHOD__ . ' needs expiration parameter to be an int.', E_USER_WARNING );
		}

		$this->_fragment_groups[$group] = array(
			'actions' => $actions,
			'expiration' => $expiration,
			'global' => $global
		);

		foreach ( $actions as $action ) {
			if ( !isset( $this->_actions[$action] ) )
				$this->_actions[$action] = array();
			$this->_actions[$action][] = $group;
		}
	}

	/**
	 * Returns registered fragment groups, ie transients.
	 *
	 * @return array array('group' => array('action1','action2'))
	 */
	function get_registered_fragment_groups() {
		return $this->_fragment_groups;
	}

	/**
	 * Returns registered actions and transient groups that should be purged per action
	 *
	 * @return array array('action' => array('group1', 'group2'))
	 */
	function get_registered_actions() {
		return $this->_actions;
	}

	function cleanup() {
		$c = Dispatcher::config();
		$engine = $c->get_string( array( 'fragmentcache', 'engine' ) );

		switch ( $engine ) {
		case 'file':
			$w3_cache_file_cleaner = new Cache_File_Cleaner( array(
					'cache_dir' => Util_Environment::cache_blog_dir( 'fragment' ),
					'clean_timelimit' => $c->get_integer( 'timelimit.cache_gc' )
				) );

			$w3_cache_file_cleaner->clean();
			break;
		}
	}
}
