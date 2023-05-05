<?php
namespace W3TC;



class Extension_Swarmify_AdminActions {
	public function w3tc_swarmify_set_key() {
		$status_val      = Util_Request::get_string( 'status' );
		$swarmcdnkey_val = Util_Request::get_string( 'swarmcdnkey' );
		if ( ! empty( $status_val ) && ! empty( $swarmcdnkey_val ) && '1' === $status_val ) {
			$config = Dispatcher::config();
			$config->set( array( 'swarmify', 'api_key' ), $swarmcdnkey_val );
			$config->save();
		}

		Util_Environment::redirect( Util_Ui::admin_url(
			'admin.php?page=w3tc_extensions&extension=swarmify&action=view' ) );
		exit();
	}
}
