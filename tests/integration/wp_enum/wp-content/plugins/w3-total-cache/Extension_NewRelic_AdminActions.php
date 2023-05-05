<?php
namespace W3TC;



class Extension_NewRelic_AdminActions {
	private $_config = null;

	function __construct() {
		$this->_config = Dispatcher::config();
	}



	function w3tc_save_new_relic() {
		$service = Dispatcher::component( 'Extension_NewRelic_Service' );
		$application = Util_Request::get_array( 'application' );
		$application['alerts_enabled'] = $application['alerts_enabled'] == 1 ? 'true' : 'false';
		$application['rum_enabled'] = $application['rum_enabled'] == 1 ? 'true' : 'false';
		$result=$service->update_application_settings( $application );
		Util_Admin::redirect( array(
				'w3tc_note' => 'new_relic_save'
			), true );
	}
}
