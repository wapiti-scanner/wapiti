<?php
namespace W3TC;

class Cdn_Highwinds_Widget {
	static public function admin_init_w3tc_dashboard() {
		$o = new Cdn_Highwinds_Widget();
		add_action( 'admin_print_styles',
			array( $o, 'admin_print_styles' ) );
		add_action( 'admin_print_scripts',
			array( $o, 'admin_print_scripts' ) );
		add_action( 'w3tc_widget_setup',
			array( $o, 'w3tc_widget_setup' ), 2000 );
	}



	public function w3tc_widget_setup() {
		Util_Widget::add( 'w3tc_highwinds',
			'<div class="w3tc-widget-highwinds-logo"></div>',
			array( $this, 'widget_form' ),
			Util_Ui::admin_url( 'admin.php?page=w3tc_cdn' ),
			'normal' );
	}



	public function widget_form() {
		$c = Dispatcher::config();
		$account_hash = $c->get_string( 'cdn.highwinds.account_hash' );
		if ( empty( $account_hash ) ) {
			include  W3TC_DIR . '/Cdn_Highwinds_Widget_View_NotConfigured.php';
			return;
		}

		$url_manage = 'https://striketracker3.highwinds.com/accounts/' .
			$account_hash . '/configure/hosts';
		$url_analyze = 'https://striketracker3.highwinds.com/accounts/' .
			$account_hash . '/analyze/overview';
		$url_purge = Util_Ui::url( array(
				'page' => 'w3tc_cdn',
				'w3tc_cdn_purge' => 'y'
			) );

		include  W3TC_DIR . '/Cdn_Highwinds_Widget_View.php';
	}




	public function admin_print_styles() {
		wp_enqueue_style( 'w3tc-widget' );
		wp_enqueue_style( 'w3tc-highwinds-widget',
			plugins_url( 'Cdn_Highwinds_Widget_View.css', W3TC_FILE ),
			array(), W3TC_VERSION );
	}



	public function admin_print_scripts() {
		wp_enqueue_script( 'google-jsapi', 'https://www.google.com/jsapi' );
		wp_enqueue_script( 'w3tc-highwinds-widget',
			plugins_url( 'Cdn_Highwinds_Widget_View.js', W3TC_FILE ),
			array(), W3TC_VERSION );
	}



	static public function w3tc_ajax_cdn_highwinds_widgetdata() {
		try {
			$core = Dispatcher::component( 'Cdn_Core' );
			$cdn = $core->get_cdn();

			$analytics = $cdn->service_analytics_transfer();

			$sum_mbytes = 0;
			$sum_mbps = 0;
			$sum_rps = 0;
			$graph = array( array( 'Date', 'Requests' ) );
			$count = count( $analytics );

			foreach ( $analytics as $item ) {
				$sum_mbytes += $item['xferUsedTotalMB'];
				$sum_mbps += $item['xferRateMeanMbps'];
				$sum_rps += $item['rpsMean'];
				$graph[] = array(
					gmdate( 'd M', $item['usageTime'] / 1000 ),
					$item['requestsCountTotal']
				);
			}

			$response = array(
				'transferred_size' => Util_Ui::format_mbytes( $sum_mbytes / $count ),
				'average_mbps' => sprintf( '%.2f', $sum_mbps / $count ),
				'average_rps' => sprintf( '%.2f', $sum_rps / $count ),
				'graph' => $graph
			);

			echo json_encode( $response );
		} catch ( \Exception $e ) {
			echo json_encode( array(
					'error' => $e->getMessage()
				) );
		}
	}
}
