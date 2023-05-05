<?php
namespace W3TC;



class Generic_Page_About extends Base_Page_Settings {
	/**
	 * Current page
	 *
	 * @var string
	 */
	protected $_page = 'w3tc_about';


	/**
	 * About tab
	 *
	 * @return void
	 */
	function view() {
		include W3TC_INC_DIR . '/options/about.php';
	}
}
