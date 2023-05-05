<?php
namespace W3TC;



class Extension_FragmentCache_Environment {
	/**
	 * Fixes environment once event occurs
	 *
	 * @throws Util_Environment_Exceptions
	 */
	static public function fix_on_event( $config, $event, $old_config = null ) {
		if ( $config->get_string( array( 'fragmentcache', 'engine' ) ) == 'file' ) {
			if ( !wp_next_scheduled( 'w3_fragmentcache_cleanup' ) ) {
				wp_schedule_event( time(),
					'w3_fragmentcache_cleanup',
					'w3_fragmentcache_cleanup' );
			}
		} else {
			self::unschedule();
		}
	}

	static public function deactivate_extension() {
		self::unschedule();
	}

	/**
	 * scheduling stuff
	 */
	static private function unschedule() {
		if ( wp_next_scheduled( 'w3_fragmentcache_cleanup' ) ) {
			wp_clear_scheduled_hook( 'w3_fragmentcache_cleanup' );
		}
	}
}
