<?php
namespace W3TC;



class Extension_NewRelic_Page extends Base_Page_Settings {
	/**
	 * Current page
	 *
	 * @var string
	 */
	protected $_page = 'w3tc_monitoring';



	public function render_content() {
		$config = Dispatcher::config();
		$monitoring_type = $config->get_string( array( 'newrelic', 'monitoring_type' ) );
		if ( $monitoring_type == 'browser' ) {
			return;
		}

		$nerser = Dispatcher::component( 'Extension_NewRelic_Service' );
		$new_relic_configured = $config->get_string( array( 'newrelic', 'api_key' ) ) &&
			$config->get_string( array( 'newrelic', 'apm.application_name' ) );
		$verify_running = $nerser->verify_running();
		$application_settings = array();

		try {
			$application_settings = $nerser->get_application_settings();
		} catch ( \Exception $ex ) {
			$application_settings = array();
		}

		if ( $view_metric = Util_Request::get_boolean( 'view_metric', false ) ) {
			$metric_names = $nerser->get_metric_names( Util_Request::get_string( 'regex', '' ) );
		}

		include  W3TC_DIR . '/Extension_NewRelic_Page_View_Apm.php';
	}
}
