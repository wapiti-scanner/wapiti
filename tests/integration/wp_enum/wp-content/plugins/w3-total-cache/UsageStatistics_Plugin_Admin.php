<?php
namespace W3TC;



class UsageStatistics_Plugin_Admin {
	function run() {
		$c = Dispatcher::config();

		add_action( 'wp_ajax_ustats_access_log_test', array( $this, 'w3tc_ajax_ustats_access_log_test' ) );
		add_filter( 'w3tc_admin_menu', array( $this, 'w3tc_admin_menu' ) );
		add_action( 'w3tc_ajax_ustats_get', array( $this, 'w3tc_ajax_ustats_get' ) );
		add_filter( 'w3tc_usage_statistics_summary_from_history', array(
				'W3TC\UsageStatistics_Sources',
				'w3tc_usage_statistics_summary_from_history'
			), 5, 2 );

		$widget = new UsageStatistics_Widget();
		$widget->init();

		add_action( 'admin_init_w3tc_dashboard', array(
				'\W3TC\UsageStatistics_Widget',
				'admin_init_w3tc_dashboard'
			) );

		add_action( 'admin_init_w3tc_general', array(
				'\W3TC\UsageStatistics_GeneralPage',
				'admin_init_w3tc_general'
			) );

		add_action( 'w3tc_config_ui_save', array(
				$this,
				'w3tc_config_ui_save'
			), 10, 2 );

		add_filter( 'w3tc_notes', array( $this, 'w3tc_notes' ) );
	}

	public function w3tc_config_ui_save( $config, $old_config ) {
		if ( $config->get( 'stats.slot_seconds' ) !=
				$old_config->get( 'stats.slot_seconds' ) ) {
			// flush all stats otherwise will be inconsistent
			$storage = new UsageStatistics_StorageWriter();
			$storage->reset();
		}
	}

	public function w3tc_notes( $notes ) {
		$c = Dispatcher::config();
		$state_master = Dispatcher::config_state_master();

		if ( $c->get_boolean( 'stats.enabled' ) &&
				!$state_master->get_boolean( 'common.hide_note_stats_enabled' ) ) {
			$notes['stats_enabled'] = sprintf(
				__( 'W3 Total Cache: Statistics collection is currently enabled. This consumes additional resources, and is not recommended to be run continuously. %s %s',
					'w3-total-cache' ),
				Util_Ui::button_link(
					__( 'Disable statistics', 'w3-total-cache' ),
					Util_Ui::url( array( 'w3tc_ustats_note_disable' => 'y' ) ),
					false, 'button',
					'w3tc_note_stats_disable' ),
				Util_Ui::button_hide_note2( array(
						'w3tc_default_config_state_master' => 'y',
						'key' => 'common.hide_note_stats_enabled',
						'value' => 'true' ) ) );
		}

		return $notes;
	}



	public function w3tc_admin_menu( $menu ) {
		$menu['w3tc_stats'] = array(
			'page_title' => __( 'Statistics', 'w3-total-cache' ),
			'menu_text' => __( 'Statistics', 'w3-total-cache' ),
			'visible_always' => false,
			'order' => 2250
		);

		return $menu;
	}



	public function w3tc_ajax_ustats_get() {
		$storage = new UsageStatistics_StorageReader();
		$summary = $storage->get_history_summary();

		if ( defined( 'W3TC_DEBUG' ) ) {
			echo json_encode( $summary ,JSON_PRETTY_PRINT );
			exit();
		}

		echo json_encode( $summary );
		exit();
	}

	/**
	 * Ajax: Test access log path.
	 */
	public function w3tc_ajax_ustats_access_log_test() {
		$nonce_val = Util_Request::get_array( '_wpnonce' )[0];
		$nonce     = isset( $nonce_val ) ? $nonce_val : false;

		if ( ! wp_verify_nonce( $nonce, 'w3tc' ) ) {
			wp_die( esc_html__( 'Invalid WordPress nonce.  Please reload the page and try again.', 'w3-total-cache' ) );
		}

		$handle       = false;
		$filename_val = Util_Request::get_string( 'filename' );
		$filepath     = ! empty( $filename_val ) ? str_replace( '://', '/', $filename_val ) : null;

		if ( $filepath ) {
			$handle   = @fopen( $filepath, 'rb' ); // phpcs:ignore WordPress
		}

		if ( $handle ) {
			esc_html_e( 'Success', 'w3-total-cache' );
		} else {
			esc_html_e( 'Failed to open file', 'w3-total-cache' );
		}

		wp_die();
	}
}
