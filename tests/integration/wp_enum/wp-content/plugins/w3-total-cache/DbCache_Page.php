<?php
namespace W3TC;



class DbCache_Page extends Base_Page_Settings {
	/**
	 * Current page
	 *
	 * @var string
	 */
	protected $_page = 'w3tc_dbcache';


	/**
	 * Database cache tab
	 *
	 * @return void
	 */
	function view() {
		$dbcache_enabled = $this->_config->get_boolean( 'dbcache.enabled' );

		include W3TC_INC_DIR . '/options/dbcache.php';
	}

	/**
	 * Database cluster config editor
	 *
	 * @return void
	 */
	function dbcluster_config() {
		$this->_page = 'w3tc_dbcluster_config';
		if ( Util_Environment::is_dbcluster() )
			$content = @file_get_contents( W3TC_FILE_DB_CLUSTER_CONFIG );
		else
			$content = @file_get_contents( W3TC_DIR . '/ini/dbcluster-config-sample.php' );

		include W3TC_INC_OPTIONS_DIR . '/enterprise/dbcluster-config.php';
	}
}
