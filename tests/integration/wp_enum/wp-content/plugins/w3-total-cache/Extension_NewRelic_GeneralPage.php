<?php
namespace W3TC;



class Extension_NewRelic_GeneralPage {
	/**
	 * W3TC General settings page modifications
	 */
	static public function admin_init_w3tc_general() {
		$o = new Extension_NewRelic_GeneralPage();

		add_filter( 'w3tc_settings_general_anchors',
			array( $o, 'w3tc_settings_general_anchors' ) );
		add_action( 'w3tc_settings_general_boxarea_monitoring',
			array( $o, 'w3tc_settings_general_boxarea_monitoring' ) );

		wp_enqueue_script( 'w3tc_extension_newrelic_popup',
			plugins_url( 'Extension_NewRelic_Popup_View.js', W3TC_FILE ),
			array( 'jquery' ), '1.0' );
	}




	public function w3tc_settings_general_anchors( $anchors ) {
		$anchors[] = array( 'id' => 'monitoring', 'text' => 'Monitoring' );
		return $anchors;
	}



	public function w3tc_settings_general_boxarea_monitoring() {
		$config = Dispatcher::config();

		$nerser = Dispatcher::component( 'Extension_NewRelic_Service' );
		$new_relic_installed = $nerser->module_is_enabled();
		$effective_appname = $nerser->get_effective_appname();

		include  W3TC_DIR . '/Extension_NewRelic_GeneralPage_View.php';
	}
}
