<?php
namespace W3TC;

/**
 * Class Generic_Plugin_WidgetCommunity.
 *
 * @since 0.14.3
 */
class Generic_WidgetCommunity {
	/**
	 * Dashboard setup action.
	 *
	 * @since 0.14.3
	 */
	static public function admin_init_w3tc_dashboard() {
		// If we're on pro, abort.
		if ( Util_Environment::is_w3tc_pro( Dispatcher::config() ) ) {
			return;
		}

		$o = new Generic_WidgetCommunity();

		add_action( 'w3tc_widget_setup', array( $o, 'wp_dashboard_setup' ), 1000 );
		add_action( 'w3tc_network_dashboard_setup', array( $o, 'wp_dashboard_setup' ), 1000 );
	}

	/**
	 * Add our community widget to the dashboard.
	 *
	 * @since 0.14.3
	 */
	function wp_dashboard_setup() {
		Util_Widget::add(
			'w3tc_community',
			'<div class="w3tc-widget-w3tc-logo"></div>' .
				'<div class="w3tc-widget-text">' .
				__( 'W3TC Community Edition', 'w3-total-cache' ) .
				'</div>',
			array( $this, 'widget_form' ),
			null,
			'normal'
		);
	}

	/**
	 * Render the content of our widget.
	 *
	 * @since 0.14.3
	 */
	public function widget_form() {
		include  W3TC_DIR . '/Generic_WidgetCommunity_View.php';
	}
}
