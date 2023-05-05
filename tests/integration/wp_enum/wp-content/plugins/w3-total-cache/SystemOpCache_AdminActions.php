<?php
namespace W3TC;



class SystemOpCache_AdminActions {
	function w3tc_opcache_flush() {
		$core = Dispatcher::component( 'SystemOpCache_Core' );
		$success = $core->flush();

		if ( $success ) {
			Util_Admin::redirect_with_custom_messages2( array(
					'notes' => array( 'OPCache was flushed successfully' )
				), true );
		} else {
			Util_Admin::redirect_with_custom_messages2( array(
					'errors' => array( 'Failed to flush OPCache' )
				), true );
		}
	}
}
