<?php
namespace W3TC;



class UsageStatistics_AdminActions {
	private $_config = null;



	public function __construct() {
		$this->_config = Dispatcher::config();
	}



	public function w3tc_ustats_note_disable() {
		$this->_config->set( 'stats.enabled', false );
		$this->_config->save();

		Util_Admin::redirect( array(), true );
	}
}
