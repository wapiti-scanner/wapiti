<?php
namespace W3TC;

class Cdn_StackPath_Widget {
	static public function admin_init_w3tc_dashboard() {
		$o = new Cdn_StackPath_Widget();
		add_action( 'admin_print_styles',
			array( $o, 'admin_print_styles' ) );
		add_action( 'admin_print_scripts',
			array( $o, 'admin_print_scripts' ) );
		add_action( 'w3tc_widget_setup',
			array( $o, 'w3tc_widget_setup' ), 2000 );
	}



	public function w3tc_widget_setup() {
		Util_Widget::add( 'w3tc_stackpath',
			'<div class="w3tc-widget-stackpath-logo"></div>',
			array( $this, 'widget_form' ),
			Util_Ui::admin_url( 'admin.php?page=w3tc_cdn' ),
			'normal' );
	}

	/**
	 * Runs plugin
	 */
	function widget_form() {
		$c = Dispatcher::config();

		// Configure authorize and have_zone
		$authorized = $c->get_string( 'cdn.stackpath.authorization_key' ) != '' &&
			$c->get_string( 'cdn.engine' ) == 'stackpath';
		$keys = explode( '+', $c->get_string( 'cdn.stackpath.authorization_key' ) );
		$authorized = $authorized  && sizeof( $keys ) == 3;
		$have_zone = $c->get_string( 'cdn.stackpath.zone_id' ) != 0;

		if ( $authorized && $have_zone ) {
			include dirname( __FILE__ ) . DIRECTORY_SEPARATOR .
				'Cdn_StackPath_Widget_View_Authorized.php';
		} else {
			include dirname( __FILE__ ) . DIRECTORY_SEPARATOR .
				'Cdn_StackPath_Widget_View_Unauthorized.php';
		}
	}



	function w3tc_ajax_cdn_stackpath_widgetdata() {
		$c = Dispatcher::config();

		require_once W3TC_LIB_NETDNA_DIR . '/NetDNAPresentation.php';
		$api = Cdn_StackPath_Api::create(
			$c->get_string( 'cdn.stackpath.authorization_key' ) );

		$zone_id = $c->get_string( 'cdn.stackpath.zone_id' );
		$response = array();

		try {
			$zone_info = $api->get_site( $zone_id );
			if ( !$zone_info )
				throw new \Exception("Zone not found");
			$filetypes = $api->get_list_of_file_types_per_zone( $zone_id );

			if ( !isset( $filetypes['filetypes'] ) )
				$filetypes['filetypes'] = array();

			$group_hits = \NetDNAPresentation::group_hits_per_filetype_group(
				$filetypes['filetypes'] );

			$graph = array( array('Filetype', 'Hits' ) );
			$colors = array();
			foreach ( $group_hits as $group => $hits ) {
				$graph[] = array( $group, $hits );
				$colors[] = \NetDNAPresentation::get_file_group_color( $group );
			}

			$response['graph'] = $graph;
			$response['colors'] = $colors;

			$summary = $api->get_stats_per_zone( $zone_id );

			$response['zone_name'] = $zone_info['name'];
			$response['summary'] = $summary;
			$response['summary_size'] = Util_Ui::format_bytes( $summary['size'] );
			$response['summary_cache_hit'] = $summary['cache_hit'];
			$response['summary_cache_hit_percentage'] = $summary['hit'] ?
				( $summary['cache_hit'] / $summary['hit'] ) * 100 :
				$summary['hit'];
        	$response['summary_noncache_hit'] = $summary['noncache_hit'];
        	$response['summary_noncache_hit_percentage'] = $summary['hit'] ?
        		( $summary['noncache_hit'] / $summary['hit'] ) * 100 :
        		$summary['hit'];

			$response['filetypes'] = $filetypes;
			$popular_files = $api->get_list_of_popularfiles_per_zone( $zone_id );
			$popular_files = \NetDNAPresentation::format_popular( $popular_files );
			$response['popular_files'] = array_slice( $popular_files, 0 , 5 );
			for ($n = 0; $n < count( $response['popular_files'] ); $n++) {
				$response['popular_files'][$n]['color'] =
					\NetDNAPresentation::get_file_group_color(
						$response['popular_files'][$n]['group'] );
			}

			$account = $api->get_account();
			$response['account_status'] = \NetDNAPresentation::get_account_status( $account['status'] );
			$response['url_manage'] = 'https://app.stackpath.com/sites/' .
				$zone_id . '/settings';
			$response['url_reports'] = 'https://app.stackpath.com/reporting/files?zone_id=' .
				$zone_id;
		} catch ( \Exception $ex ) {
			$response['error'] = $ex->getMessage();
		}

		echo json_encode( $response );
	}





	public function admin_print_styles() {
		wp_enqueue_style( 'w3tc-widget' );
		wp_enqueue_style( 'w3tc-stackpath-widget',
			plugins_url( 'Cdn_StackPath_Widget_View.css', W3TC_FILE ),
			array(), W3TC_VERSION );
	}



	public function admin_print_scripts() {
		wp_enqueue_style( 'w3tc-widget' );
		wp_enqueue_script( 'google-jsapi', 'https://www.google.com/jsapi');
		wp_enqueue_script( 'w3tc-stackpath-widget',
			plugins_url( 'Cdn_StackPath_Widget_View.js', W3TC_FILE ),
			array( 'google-jsapi' ), W3TC_VERSION );
		wp_enqueue_script( 'w3tc-metadata' );
		wp_enqueue_script( 'w3tc-widget' );
	}

}
