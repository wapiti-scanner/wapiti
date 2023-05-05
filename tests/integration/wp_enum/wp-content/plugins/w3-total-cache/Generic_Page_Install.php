<?php
namespace W3TC;



class Generic_Page_Install extends Base_Page_Settings {
	/**
	 * Current page
	 *
	 * @var string
	 */
	protected $_page = 'w3tc_install';

	/**
	 * Install tab
	 *
	 * @return void
	 */
	function view() {
		$rewrite_rules_descriptors = array();

		if ( Util_Rule::can_check_rules() ) {
			$e = Dispatcher::component( 'Root_Environment' );
			$rewrite_rules_descriptors = $e->get_required_rules( $this->_config );
			$other_areas = $e->get_other_instructions( $this->_config );
		}

		include W3TC_INC_DIR . '/options/install.php';
	}
}
