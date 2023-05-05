<?php
namespace W3TC;

class Cdn_StackPath2_Widget {
	static public function admin_init_w3tc_dashboard() {
		$o = new Cdn_StackPath2_Widget();
		add_action( 'admin_print_styles',
			array( $o, 'admin_print_styles' ) );
		add_action( 'admin_print_scripts',
			array( $o, 'admin_print_scripts' ) );

		Util_Widget::add2( 'w3tc_stackpath', 2000,
			'<div class="w3tc-widget-stackpath2-logo"></div>',
			array( $o, 'widget_form' ),
			Util_Ui::admin_url( 'admin.php?page=w3tc_cdn' ),
			'normal' );
	}

	/**
	 * Runs plugin
	 */
	function widget_form() {
		$c = Dispatcher::config();

		// Configure authorize and have_zone
		$authorized = $c->get_string( 'cdn.stackpath2.client_id' ) != '' &&
			$c->get_string( 'cdn.engine' ) == 'stackpath2';

		if ( $authorized ) {
			include dirname( __FILE__ ) . DIRECTORY_SEPARATOR .
				'Cdn_StackPath2_Widget_View_Authorized.php';
		} else {
			include dirname( __FILE__ ) . DIRECTORY_SEPARATOR .
				'Cdn_StackPath2_Widget_View_Unauthorized.php';
		}
	}



	static function w3tc_ajax_cdn_stackpath2_widgetdata() {
		$c = Dispatcher::config();
		$cs = Dispatcher::config_state();

		$api = new Cdn_StackPath2_Api( array(
			'client_id' => $c->get_string( 'cdn.stackpath2.client_id' ),
			'client_secret' => $c->get_string( 'cdn.stackpath2.client_secret' ),
			'stack_id' => $c->get_string( 'cdn.stackpath2.stack_id' ),
			'access_token' => $cs->get_string( 'cdn.stackpath2.access_token' )
		) );

		$stack_id = $c->get_string( 'cdn.stackpath2.stack_id' );
		$site_id = $c->get_string( 'cdn.stackpath2.site_id' );
		$response = array();

		try {
			$r = $api->site_metrics( $site_id, 7 );
			$series = $r['series'][0];

			$keys = $series['metrics'];
			$stats = array();
			foreach ($series['samples'] as $sample) {
				$row = array();
				for ( $n = 0; $n < count( $keys ); $n++ ) {
					$row[$keys[$n]] = $sample['values'][$n];
				}

				$stats[] = $row;
			}

			$total_mb = 0;
			$total_requests = 0;
			$chart_mb = array( array('Date', 'MB', 'Requests' ) );

			$dd = new \DateTime();

			foreach ($stats as $r) {
				$total_mb += $r['xferUsedTotalMB'];
				$total_requests += $r['requestsCountTotal'];
				$d = $dd->setTimestamp( (int)$r['usageTime'] );
				$chart_mb[] = array(
					$d->format( 'M/d' ),
					$r['xferUsedTotalMB'],
					$r['requestsCountTotal']
				);
			}

			$response['summary_mb'] = sprintf( '%.2f MB', $total_mb );
			$response['summary_requests'] = $total_requests;
			$response['chart_mb'] = $chart_mb;

			$response['url_manage'] =
				"https://control.stackpath.com/stacks/$stack_id/cdn/sites/$site_id/cache";
			$response['url_reports'] =
				"https://control.stackpath.com/stacks/$stack_id/cdn/sites/$site_id/overview";
		} catch ( \Exception $ex ) {
			$response['error'] = $ex->getMessage();
		}

		echo json_encode( $response );
	}





	public function admin_print_styles() {
		wp_enqueue_style( 'w3tc-widget' );
		wp_enqueue_style( 'w3tc-stackpath-widget',
			plugins_url( 'Cdn_StackPath2_Widget_View.css', W3TC_FILE ),
			array(), W3TC_VERSION );
	}



	public function admin_print_scripts() {
		wp_enqueue_style( 'w3tc-widget' );
		wp_enqueue_script( 'google-jsapi', 'https://www.google.com/jsapi');
		wp_enqueue_script( 'w3tc-stackpath-widget',
			plugins_url( 'Cdn_StackPath2_Widget_View.js', W3TC_FILE ),
			array( 'google-jsapi' ), W3TC_VERSION );
		wp_enqueue_script( 'w3tc-metadata' );
		wp_enqueue_script( 'w3tc-widget' );
	}

}
