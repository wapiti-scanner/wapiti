<?php
namespace W3TC;

class Generic_WidgetBoldGrid {
	static public function admin_init_w3tc_dashboard() {
		$show = apply_filters( 'w3tc_generic_boldgrid_show', self::should_show_widget() );
		if ( !$show ) {
			return;
		}

		$o = new Generic_WidgetBoldGrid();

		Util_Widget::add2( 'w3tc_boldgrid', 5000,
			'<div class="w3tc-widget-boldgrid-logo"></div>',
			array( $o, 'widget_form' ),
			self_admin_url(
				'plugin-install.php?tab=plugin-information&amp;plugin=boldgrid-backup' .
				'&amp;TB_iframe=true&amp;width=772&amp;height=550'
			), 'normal', __( 'View Details' ), 'thickbox open-plugin-details-modal' );

		add_thickbox();
		wp_enqueue_script( 'plugin-install' );

		wp_enqueue_script( 'w3tc-boldgrid-widget',
			plugins_url( 'Generic_WidgetBoldGrid_View.js', W3TC_FILE ),
			array( 'thickbox' ), W3TC_VERSION );
	}



	/**
	 * Determine whether or not we should show the backup widget.
	 *
	 * We will only recommend the backup plugin if we detect that the user is not already
	 * running a popular WordPress backup plugin.
	 *
	 * @since 0.11.0
	 *
	 * @return bool
	 */
	static private function should_show_widget() {
		$plugins = get_option( 'active_plugins' );

		$backup_plugins = array(
			'backup/backup.php',
			'backwpup/backwpup.php',
			'boldgrid-backup/boldgrid-backup.php',
			'duplicator/duplicator.php',
			'updraftplus/updraftplus.php',
			'wpvivid-backuprestore/wpvivid-backuprestore.php'
		);

		foreach ( $plugins as $plugin ) {
			if ( in_array( $plugin, $backup_plugins ) ) {
				return false;
			}
		}

		return true;
	}



	public function widget_form() {
		$install_url = wp_nonce_url(
			'admin.php?page=w3tc_dashboard&w3tc_boldgrid_install', 'w3tc' );

		include  W3TC_DIR . '/Generic_WidgetBoldGrid_View.php';
	}
}
