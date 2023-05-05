<?php
namespace W3TC;



class Extension_FragmentCache_GeneralPage {
	/**
	 * W3TC General settings page modifications
	 */
	static public function admin_init_w3tc_general() {
		$o = new Extension_FragmentCache_GeneralPage();

		add_filter( 'w3tc_settings_general_anchors',
			array( $o, 'w3tc_settings_general_anchors' ) );
		add_action( 'w3tc_settings_general_boxarea_fragmentcache',
			array( $o, 'w3tc_settings_general_boxarea_fragmentcache' ) );
	}




	public function w3tc_settings_general_anchors( $anchors ) {
		$anchors[] = array( 'id' => 'fragmentcache', 'text' => 'Fragment Cache' );
		return $anchors;
	}



	public function w3tc_settings_general_boxarea_fragmentcache() {
		include  W3TC_DIR . '/Extension_FragmentCache_GeneralPage_View.php';
	}
}
