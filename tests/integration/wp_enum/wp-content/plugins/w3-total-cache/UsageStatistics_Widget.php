<?php
namespace W3TC;

/**
 * widget with stats
 */
class UsageStatistics_Widget {
	static private function enabled() {
		static $_enabled = null;
		if ( is_null( $_enabled ) ) {
			$c = Dispatcher::config();
			$_enabled = ( $c->get_boolean( 'stats.enabled' ) &&
				Util_Environment::is_w3tc_pro( $c ) );
		}

		return $_enabled;
	}



	public function init() {
		Util_Widget::add2( 'w3tc_usage_statistics', 1000,
			'<div class="w3tc-widget-w3tc-logo"></div>' .
			'<div class="w3tc-widget-text">' .
			__( 'Caching Statistics', 'w3-total-cache' ) .
			'</div>',
			array( $this, 'widget_form' ),
			Util_Ui::admin_url( 'admin.php?page=w3tc_stats' ),
			'normal',
			 'Detailed' );
	}



	static public function admin_init_w3tc_dashboard() {
		if ( self::enabled() ) {
			wp_enqueue_script( 'w3tc-canvasjs',
				plugins_url( 'pub/js/chartjs.min.js', W3TC_FILE ),
				array(), W3TC_VERSION );
			wp_enqueue_script( 'w3tc-widget-usagestatistics',
				plugins_url( 'UsageStatistics_Widget_View.js', W3TC_FILE ),
				array(), W3TC_VERSION );
		}
	}



	public function widget_form() {
		if ( self::enabled() ) {
			include  W3TC_DIR . '/UsageStatistics_Widget_View.php';
		} else {
			include  W3TC_DIR . '/UsageStatistics_Widget_View_Disabled.php';
		}
	}
}
