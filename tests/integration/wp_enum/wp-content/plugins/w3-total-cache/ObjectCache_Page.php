<?php
namespace W3TC;



class ObjectCache_Page extends Base_Page_Settings {
	/**
	 * Current page
	 *
	 * @var string
	 */
	protected $_page = 'w3tc_objectcache';

	/**
	 * Objects cache tab
	 *
	 * @return void
	 */
	function view() {
		$objectcache_enabled = $this->_config->get_boolean( 'objectcache.enabled' );

		include W3TC_INC_DIR . '/options/objectcache.php';
	}

}
