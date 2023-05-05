<?php
namespace W3TC;



class Cdn_StackPath2_Popup {
	static public function w3tc_ajax() {
		$o = new Cdn_StackPath2_Popup();

		add_action( 'w3tc_ajax_cdn_stackpath2_intro',
			array( $o, 'w3tc_ajax_cdn_stackpath2_intro' ) );
		add_action( 'w3tc_ajax_cdn_stackpath2_list_stacks',
			array( $o, 'w3tc_ajax_cdn_stackpath2_list_stacks' ) );
		add_action( 'w3tc_ajax_cdn_stackpath2_list_sites',
			array( $o, 'w3tc_ajax_cdn_stackpath2_list_sites' ) );
		add_action( 'w3tc_ajax_cdn_stackpath2_configure_site',
			array( $o, 'w3tc_ajax_cdn_stackpath2_configure_site' ) );
	}



	public function w3tc_ajax_cdn_stackpath2_intro() {
		$config = Dispatcher::config();

		$this->render_intro( array(
			'client_id' => $config->get_string( 'cdn.stackpath2.client_id' ),
			'client_secret' => $config->get_string( 'cdn.stackpath2.client_secret' )
		) );
	}



	private function render_intro( $details ) {
		$config = Dispatcher::config();
		$url_obtain_key = W3TC_STACKPATH2_AUTHORIZE_URL;

		include  W3TC_DIR . '/Cdn_StackPath2_Popup_View_Intro.php';
		exit();
	}



	public function w3tc_ajax_cdn_stackpath2_list_stacks() {
		$api_config = array(
			'client_id' => Util_Request::get_string( 'client_id' ),
			'client_secret' => Util_Request::get_string( 'client_secret' )
		);

		$api = new Cdn_StackPath2_Api( $api_config );

		try {
			$r = $r = $api->stacks_list();
			$stacks = $r['results'];
		} catch ( \Exception $ex ) {
			$error_message = 'Can\'t authenticate: ' . $ex->getMessage();

			$this->render_intro( array(
					'client_id' => $api_config['client_id'],
					'client_secret' => $api_config['client_secret'],
					'error_message' => $error_message
				) );
			exit();
		}

		$count = 0;
		$stack_id = '';
		foreach ( $stacks as $i ) {
			if ( $i['status'] == 'ACTIVE' ) {
				$count++;
				$stack_id = $i['id'];
			}
		}

		if ( $count == 1 ) {
			$api_config['stack_id'] = $stack_id;
			$this->_w3tc_ajax_cdn_stackpath2_list_sites( $api_config );
			exit();
		}

		$details = array(
			'api_config' => $this->api_config_encode( $api_config ),
			'stacks' => $stacks
		);

		include  W3TC_DIR . '/Cdn_StackPath2_Popup_View_Stacks.php';
		exit();
	}



	public function w3tc_ajax_cdn_stackpath2_list_sites() {
		$api_config = $this->api_config_decode( Util_Request::get_string( 'api_config' ) );
		$api_config['stack_id'] = Util_Request::get_string( 'stack_id' );
		$this->_w3tc_ajax_cdn_stackpath2_list_sites( $api_config );
	}



	private function _w3tc_ajax_cdn_stackpath2_list_sites( $api_config ) {
		$api = new Cdn_StackPath2_Api( $api_config );

		try {
			$r = $api->site_list();
			$sites = $r['results'];
		} catch ( \Exception $ex ) {
			$error_message = 'Can\'t authenticate: ' . $ex->getMessage();

			$this->render_intro( array(
					'client_id' => $api_config['client_id'],
					'client_secret' => $api_config['client_secret'],
					'stack_id' => $api_config['stack_id'],
					'error_message' => $error_message
				) );
			exit();
		}

		$details = array(
			'api_config' => $this->api_config_encode( $api_config ),
			'sites' => $sites,
			'new_hostname' => parse_url( home_url(), PHP_URL_HOST )
		);

		include  W3TC_DIR . '/Cdn_StackPath2_Popup_View_Sites.php';
		exit();
	}



	public function w3tc_ajax_cdn_stackpath2_configure_site() {
		$api_config = $this->api_config_decode( Util_Request::get_string( 'api_config' ) );
		$site_id = Util_Request::get( 'site_id', '' );

		$api = new Cdn_StackPath2_Api( $api_config );
		$cors_present = false;

		try {
			if ( empty( $site_id ) ) {
				// create new zone mode
				$hostname = parse_url( home_url(), PHP_URL_HOST );

				$r = $api->site_create( array(
					'domain' => $hostname,
					'origin' => array(
						'path' => '/',
						'hostname' => $hostname,
						'port' => 80,
						'securePort' => 443
					),
					'features' => array( 'CDN' )
				) );

				$site_id = $r['site']['id'];
			}

			$r = $api->site_dns_targets_get( $site_id );
			$domains = $r['addresses'];

			$cds = $api->site_cds_get( $site_id );

			if ( isset( $cds['configuration'] ) &&
					isset( $cds['configuration']['staticHeader'] ) ) {
				$headers = $cds['configuration']['staticHeader'];

				$cors_present = isset( $headers[0] ) &&
					isset( $headers[0]['http'] ) &&
					preg_match( '/access\-control\-allow\-origin/i', $headers[0]['http'] );
			}
		} catch ( \Exception $ex ) {
			$this->render_intro( array(
					'client_id' => $api_config['client_id'],
					'client_secret' => $api_config['client_secret'],
					'stack_id' => $api_config['stack_id'],
					'error_message' => 'Can\'t obtain site: ' . $ex->getMessage()
				) );
			exit();
		}

		$c = Dispatcher::config();
		$c->set( 'cdn.stackpath2.client_id', $api_config['client_id'] );
		$c->set( 'cdn.stackpath2.client_secret', $api_config['client_secret'] );
		$c->set( 'cdn.stackpath2.stack_id', $api_config['stack_id'] );
		$c->set( 'cdn.stackpath2.site_id', $site_id );
		$c->set( 'cdn.stackpath2.site_root_domain', $domains[0] );
		$c->set( 'cdn.stackpath2.domain', $domains );
		$c->set( 'cdn.cors_header', !$cors_present );
		$c->save();

		include  W3TC_DIR . '/Cdn_StackPath2_Popup_View_Success.php';
		exit();
	}



	private function api_config_encode( $c ) {
		return implode( ';', array(
			$c['client_id'], $c['client_secret'],
			isset( $c['stack_id'] ) ? $c['stack_id'] : ''
		) );
	}



	private function api_config_decode( $s ) {
		$a = explode( ';', $s );
		return array(
			'client_id' => $a[0],
			'client_secret' => $a[1],
			'stack_id' => $a[2]
		);
	}
}
