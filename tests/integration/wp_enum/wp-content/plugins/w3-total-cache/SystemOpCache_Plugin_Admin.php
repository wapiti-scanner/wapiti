<?php
namespace W3TC;

class SystemOpCache_Plugin_Admin {
	function run() {
		if ( Util_Installed::opcache() || Util_Installed::apc_opcache() ) {
			add_filter( 'w3tc_admin_bar_menu',
				array( $this, 'w3tc_admin_bar_menu' ) );
		}

		add_filter( 'w3tc_admin_actions',
			array( $this, 'w3tc_admin_actions' ) );
		add_action( 'w3tc_settings_general_boxarea_system_opcache',
			array( $this, 'w3tc_settings_general_boxarea_system_opcache' ) );
	}



	public function w3tc_settings_general_anchors( $anchors ) {
		$anchors[] = array( 'id' => 'system_opcache', 'text' => 'System OPcache' );
		return $anchors;
	}



	static public function w3tc_admin_actions( $handlers ) {
		$handlers['opcache'] = 'SystemOpCache_AdminActions';

		return $handlers;
	}



	public function w3tc_settings_general_boxarea_system_opcache() {
		$opcode_engine = 'Not Available';
		$validate_timestamps = false;

		if ( Util_Installed::opcache() ) {
			$opcode_engine = 'OPcache';
			$validate_timestamps = Util_Installed::is_opcache_validate_timestamps();
		} else if ( Util_Installed::apc_opcache() ) {
				$opcode_engine = 'APC';
				$engine_status = Util_Installed::is_apc_validate_timestamps();
			}

		include  W3TC_DIR . '/SystemOpCache_GeneralPage_View.php';
	}



	public function w3tc_admin_bar_menu( $menu_items ) {
		$menu_items['20910.system_opcache'] = array(
			'id' => 'w3tc_flush_opcache',
			'parent' => 'w3tc_flush',
			'title' => __( 'Opcode Cache', 'w3-total-cache' ),
			'href' => Util_Ui::url( array( 'page' => 'w3tc_dashboard', 'w3tc_opcache_flush' => '' ) ),
		);

		return $menu_items;
	}
}
