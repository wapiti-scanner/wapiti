<?php
namespace W3TC;



class Extension_NewRelic_Widget {
	private $_config = null;



	static public function w3tc_ajax() {
		$o = new Extension_NewRelic_Widget();

		add_action( 'w3tc_ajax_newrelic_widgetdata_basic', array(
				$o, 'w3tc_ajax_newrelic_widgetdata_basic' ) );
		add_action( 'w3tc_ajax_newrelic_widgetdata_pageloads', array(
				$o, 'w3tc_ajax_newrelic_widgetdata_pageloads' ) );
		add_action( 'w3tc_ajax_newrelic_widgetdata_webtransactions', array(
				$o, 'w3tc_ajax_newrelic_widgetdata_webtransactions' ) );
		add_action( 'w3tc_ajax_newrelic_widgetdata_dbtimes', array(
				$o, 'w3tc_ajax_newrelic_widgetdata_dbtimes' ) );
	}



	static public function admin_init_w3tc_dashboard() {
		$o = new Extension_NewRelic_Widget();
		$o->_config = Dispatcher::config();

		add_action( 'w3tc_widget_setup', array( $o, 'wp_dashboard_setup' ), 9000 );
		add_action( 'w3tc_network_dashboard_setup',
			array( $o, 'wp_dashboard_setup' ), 9000 );

		$nerser = Dispatcher::component( 'Extension_NewRelic_Service' );
		$view_application = $nerser->get_effective_application_id();
		$new_relic_configured =
			( $o->_config->get_string( array( 'newrelic', 'api_key' ) ) &&
			$view_application != 0 );
		$monitoring_type = $o->_config->get_string( array(
				'newrelic', 'monitoring_type' ) );
		if ( $monitoring_type != 'browser' ) {
			wp_enqueue_script( 'w3tc-widget-newrelic',
				plugins_url( 'Extension_NewRelic_Widget_View.js', W3TC_FILE ),
				array(), W3TC_VERSION );
		}


		wp_enqueue_style( 'w3tc-widget-newrelic',
			plugins_url( 'Extension_NewRelic_Widget_View.css', W3TC_FILE ),
			array(), W3TC_VERSION );
	}



	/**
	 * Dashboard setup action
	 *
	 * @return void
	 */
	function wp_dashboard_setup() {
		$nerser = Dispatcher::component( 'Extension_NewRelic_Service' );

		$view = '';

		$view_application = $nerser->get_effective_application_id();
		$new_relic_configured =
			( $this->_config->get_string( array( 'newrelic', 'api_key' ) ) &&
			$view_application != 0 );

		if ( $new_relic_configured ) {
			$view_vis = sprintf(
				"https://rpm.newrelic.com/accounts/%d/applications/%d",
				$nerser->get_account_id(),
				$nerser->get_effective_application_id() );
			$view = '<div class="w3tc-widget-text"><a href="' .
				$view_vis . '">' .
				__( 'view visualizations', 'w3-total-cache' ) . '</a></div>';
		}

		Util_Widget::add( 'w3tc_new_relic',
			'<div class="w3tc-widget-newrelic-logo"></div>' . $view,
			array( $this, 'widget_new_relic' ),
			Util_Ui::admin_url( 'admin.php?page=w3tc_general#monitoring' ),
			'normal' );
	}



	/**
	 * Loads and configured New Relic widget to be used in WP Dashboards.
	 *
	 * @param unknown $widget_id
	 * @param array   $form_inputs
	 */
	function widget_new_relic( $widget_id, $form_inputs = array() ) {
		$nerser = Dispatcher::component( 'Extension_NewRelic_Service' );
		$view_application = $nerser->get_effective_application_id();
		$new_relic_configured =
			( $this->_config->get_string( array( 'newrelic', 'api_key' ) ) &&
			$view_application != 0 );
		if ( !$new_relic_configured ) {
			include  W3TC_DIR . '/Extension_NewRelic_Widget_View_NotConfigured.php';
			return;
		}

		$monitoring_type = $this->_config->get_string( array(
				'newrelic', 'monitoring_type' ) );
		if ( $monitoring_type == 'browser' )
			include  W3TC_DIR . '/Extension_NewRelic_Widget_View_Browser.php';
		else
			include  W3TC_DIR . '/Extension_NewRelic_Widget_View_Apm.php';
	}



	/**
	 * Gives data for widget content
	 */
	public function w3tc_ajax_newrelic_widgetdata_basic() {
		// cache status for some small time
		$response = get_transient( 'w3tc_nr_widgetdata_basic' );
		$response = @json_decode( $response, true );
		if ( is_array( $response ) && isset( $response['time'] ) &&
			$response['time'] >= time() - 60 ) {
			echo json_encode( $response );
			return;
		}

		$service = Dispatcher::component( 'Extension_NewRelic_Service' );
		$verify_running = $service->verify_running();

		$response = array(
			'time' => time()
		);

		if ( !is_array( $verify_running ) )
			$response['php_agent'] = '<span class="w3tc-enabled">enabled</span>';
		else
			$response['php_agent'] = '<span class="w3tc-disabled">disabled</span>';

		try {
			$subscription = $service->get_subscription();
			$response['subscription_level'] = $subscription['product-name'];

			$summary = $service->get_application_summary();
			$this->_fill( $response, 'apdex', $summary, 'Apdex' );
			$this->_fill( $response, 'application_busy', $summary,
				'Application Busy' );
			$this->_fill( $response, 'error_rate', $summary, 'Error Rate' );
			$this->_fill( $response, 'throughput', $summary, 'Throughput' );
			$this->_fill( $response, 'errors', $summary, 'Errors' );
			$this->_fill( $response, 'response_time', $summary, 'Response Time' );
			$this->_fill( $response, 'db', $summary, 'DB' );
			$this->_fill( $response, 'cpu', $summary, 'CPU' );
			$this->_fill( $response, 'memory', $summary, 'Memory' );

			$can_use_metrics = $service->can_get_metrics();
			if ( $can_use_metrics ) {
				$dashboard_metrics = $service->get_dashboard_metrics();
				$this->_fill_avg( $response, 'enduser', $dashboard_metrics,
					'EndUser' );
				$this->_fill_avg( $response, 'webtransaction', $dashboard_metrics,
					'WebTransaction' );
				$this->_fill_avg( $response, 'database', $dashboard_metrics,
					'Database' );
			}

			// load data for notification here too
			$pl = $service->get_frontend_response_time();
			update_option( 'w3tc_nr_frontend_response_time', $pl );
		} catch ( \Exception $ex ) {
		}

		set_transient( 'w3tc_nr_widgetdata_basic', json_encode( $response ), 60 );
		echo json_encode( $response );
	}



	public function w3tc_ajax_newrelic_widgetdata_pageloads() {
		$response = array(
			'content' => '<div class="w3tcnr_topfive_message">No data available</div>'
		);

		try {
			$service = Dispatcher::component( 'Extension_NewRelic_Service' );
			$can_use_metrics = $service->can_get_metrics();
			if ( $can_use_metrics ) {
				$metric_slow_pages = $service->get_slowest_page_load();
				if ( count( $metric_slow_pages ) > 0 ) {
					$s = '<table class="w3tcnr_slowest">';

					foreach ( $metric_slow_pages as $transaction => $time ) {
						$s .= '<tr><td><span>' . $transaction .
							'</span></td><td>' . Util_Ui::secs_to_time( $time ) .
							'</td></tr>';
					}

					$s .= '</table>';
					$response['content'] = $s;
				}
			}
		} catch ( \Exception $e ) {
			$response['content'] = '<div class="w3tcnr_topfive_message">Error occurred</div>';
		}

		echo json_encode( $response );
	}



	public function w3tc_ajax_newrelic_widgetdata_webtransactions() {
		$response = array(
			'content' => '<div class="w3tcnr_topfive_message">No data available</div>'
		);

		try {
			$service = Dispatcher::component( 'Extension_NewRelic_Service' );
			$can_use_metrics = $service->can_get_metrics();
			if ( $can_use_metrics ) {
				$metric_slow = $service->get_slowest_webtransactions();
				if ( count( $metric_slow ) > 0 ) {
					$s = '<table class="w3tcnr_slowest">';

					foreach ( $metric_slow as $transaction => $time ) {
						$s .= '<tr><td><span>' . $transaction .
							'</span></td><td>' . Util_Ui::secs_to_time( $time ) .
							'</td></tr>';
					}

					$s .= '</table>';
					$response['content'] = $s;
				}
			}
		} catch ( \Exception $e ) {
			$response['content'] = '<div class="w3tcnr_topfive_message">Error occurred</div>';
		}

		echo json_encode( $response );
	}




	public function w3tc_ajax_newrelic_widgetdata_dbtimes() {
		$response = array(
			'content' => '<div class="w3tcnr_topfive_message">No data available</div>'
		);

		try {
			$service = Dispatcher::component( 'Extension_NewRelic_Service' );
			$can_use_metrics = $service->can_get_metrics();
			if ( $can_use_metrics ) {
				$metric_slow = $service->get_slowest_database();
				if ( count( $metric_slow ) > 0 ) {
					$s = '<table class="w3tcnr_slowest">';

					foreach ( $metric_slow as $transaction => $time ) {
						$s .= '<tr><td><span>' . $transaction .
							'</span></td><td>' . Util_Ui::secs_to_time( $time ) .
							'</td></tr>';
					}

					$s .= '</table>';
					$response['content'] = $s;
				}
			}
		} catch ( \Exception $e ) {
			$response['content'] = '<div class="w3tcnr_topfive_message">Error occurred</div>';
		}

		echo json_encode( $response );
	}



	private function _fill( &$response, $response_key, $summary, $summary_key ) {
		if ( isset( $summary[$summary_key] ) )
			$response[$response_key] = $summary[$summary_key];
	}



	private function _fill_avg( &$response, $response_key, $metrics, $metric_key ) {
		if ( !isset( $metrics[$metric_key] ) )
			return;

		$data = $metrics[$metric_key];
		$response[$response_key] = Util_Ui::secs_to_time(
			array_shift( $data[0] )->average_response_time
		);
	}
}
