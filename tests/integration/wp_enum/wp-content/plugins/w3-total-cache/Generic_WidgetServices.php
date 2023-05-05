<?php
namespace W3TC;
/**
 * W3 Forum Widget
 */



/**
 * Class Generic_Plugin_WidgetServices
 */
class Generic_WidgetServices {
	function __construct() {
	}

	/**
	 * Dashboard setup action
	 *
	 * @return void
	 */
	static public function admin_init_w3tc_dashboard() {
		$o = new Generic_WidgetServices();

		add_action( 'w3tc_widget_setup', array( $o, 'wp_dashboard_setup' ), 5000 );
		add_action( 'w3tc_network_dashboard_setup',
			array( $o, 'wp_dashboard_setup' ), 5000 );
	}

	function wp_dashboard_setup() {
		Util_Widget::add( 'w3tc_services',
			'<div class="w3tc-widget-w3tc-logo"></div>' .
			'<div class="w3tc-widget-text">' .
			__( 'Premium Services', 'w3-total-cache' ) .
			'</div>',
			array( $this, 'widget_form' ),
			null, 'normal' );
	}



	public function load_request_types() {
		$v = get_site_option( 'w3tc_generic_widgetservices' );
		try {
			$v = json_decode( $v, true );
			if ( isset( $v['items'] ) && isset( $v['expires'] ) &&
				$v['expires'] > time() )
				return $v['items'];
		} catch ( \Exception $e ) {
		}


		$result = wp_remote_request( W3TC_SUPPORT_SERVICES_URL,
			array( 'method' => 'GET' ) );

		if ( is_wp_error( $result ) )
			return null;

		$response_json = json_decode( $result['body'], true );

		if ( is_null( $response_json ) || !isset( $response_json['items'] ) )
			return null;

		update_site_option( 'w3tc_generic_widgetservices',
			json_encode( array(
				'content' => $response_json,
				'expires' => time() + 3600 * 24 * 7
			) ) );

		return $response_json['items'];
	}



	public function widget_form() {
		$items = $this->load_request_types();

		include  W3TC_DIR . '/Generic_WidgetServices_View.php';
	}

/*
		wp_enqueue_style( 'w3tc-widget-newrelic',
			plugins_url( 'Extension_NewRelic_Widget_View.css', W3TC_FILE ),
			array(), W3TC_VERSION );

		if ( Util_Admin::get_current_wp_page() == 'w3tc_dashboard' )
			add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );

		$this->_json_request_types = array(
			'email_support' => sprintf( __( 'Less than 15 Minute Email Support Response %s', 'w3-total-cache' ), '(M-F 9AM - 5PM EDT): $175 USD' ),
			'phone_support' => sprintf( __( 'Less than 15 Minute Phone Support Response %s', 'w3-total-cache' ), '(M-F 9AM - 5PM EDT): $250 USD' ),
			'plugin_config' => sprintf( __( 'Professional Plugin Configuration %s', 'w3-total-cache' ), 'Starting @ $200 USD' ),
			'theme_config' => sprintf( __( 'Theme Performance Optimization & Plugin Configuration %s', 'w3-total-cache' ), 'Starting @ $350 USD' ),
			'linux_config' => sprintf( __( 'Linux Server Optimization & Plugin Configuration %s', 'w3-total-cache' ), 'Starting @ $450 USD' )
		);
		$this->_request_types = array(
			'email_support' => sprintf( __( 'Less than 15 Minute Email Support Response %s', 'w3-total-cache' ), '<br /><span>(M-F 9AM - 5PM EDT): $175 USD</span>' ),
			'phone_support' => sprintf( __( 'Less than 15 Minute Phone Support Response %s', 'w3-total-cache' ), '<br /><span>(M-F 9AM - 5PM EDT): $250 USD</span>' ),
			'plugin_config' => sprintf( __( 'Professional Plugin Configuration %s', 'w3-total-cache' ), '<br /><span>Starting @ $200 USD</span>' ),
			'theme_config' => sprintf( __( 'Theme Performance Optimization & Plugin Configuration %s', 'w3-total-cache' ), '<br /><span>Starting @ $350 USD</span>' ),
			'linux_config' => sprintf( __( 'Linux Server Optimization & Plugin Configuration %s', 'w3-total-cache' ), '<br /><span>Starting @ $450 USD</span>' )
		);

	function widget_form() {
		include W3TC_INC_WIDGET_DIR . '/services.php';
	}

	public function enqueue() {
		wp_enqueue_style( 'w3tc-widget' );
		wp_enqueue_script( 'w3tc-metadata' );
		wp_enqueue_script( 'w3tc-widget' );
	}*/
}
