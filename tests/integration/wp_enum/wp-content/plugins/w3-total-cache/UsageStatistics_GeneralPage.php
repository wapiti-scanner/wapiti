<?php
namespace W3TC;



class UsageStatistics_GeneralPage {
	/**
	 * W3TC General settings page modifications
	 */
	static public function admin_init_w3tc_general() {
		$o = new UsageStatistics_GeneralPage();

		add_filter( 'w3tc_settings_general_anchors',
			array( $o, 'w3tc_settings_general_anchors' ) );
		add_action( 'w3tc_settings_general_boxarea_stats',
			array( $o, 'w3tc_settings_general_boxarea_stats' ) );
	}




	public function w3tc_settings_general_anchors( $anchors ) {
		$anchors[] = array(
			'id'   => 'stats',
			'text' => __( 'Statistics', 'w3-total-cache' ),
		);
		return $anchors;
	}



	public function w3tc_settings_general_boxarea_stats() {
		include  W3TC_DIR . '/UsageStatistics_GeneralPage_View.php';
	}
}
