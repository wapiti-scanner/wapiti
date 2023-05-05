<?php
namespace W3TC;



class Cdn_Highwinds_Popup {
	static public function w3tc_ajax() {
		$o = new Cdn_Highwinds_Popup();

		add_action( 'w3tc_ajax_cdn_highwinds_authenticate',
			array( $o, 'w3tc_ajax_cdn_highwinds_authenticate' ) );
		add_action( 'w3tc_ajax_cdn_highwinds_select_host',
			array( $o, 'w3tc_ajax_cdn_highwinds_select_host' ) );
		add_action( 'w3tc_ajax_cdn_highwinds_configure_host',
			array( $o, 'w3tc_ajax_cdn_highwinds_configure_host' ) );
		add_action( 'w3tc_ajax_cdn_highwinds_configure_cnames_form',
			array( $o, 'w3tc_ajax_cdn_highwinds_configure_cnames_form' ) );
		add_action( 'w3tc_ajax_cdn_highwinds_configure_cnames',
			array( $o, 'w3tc_ajax_cdn_highwinds_configure_cnames' ) );
	}



	public function w3tc_ajax_cdn_highwinds_authenticate() {
		$details = array();
		include  W3TC_DIR . '/Cdn_Highwinds_Popup_View_Intro.php';
		exit();
	}



	public function w3tc_ajax_cdn_highwinds_select_host() {
		$api_token = Util_Request::get_string( 'api_token' );

		try {
			$user = Cdn_Highwinds_Api::users_me( $api_token );
			$account_hash = $user['accountHash'];

			// obtain hosts
			$api = new Cdn_Highwinds_Api( $account_hash, $api_token );
			$hosts_response = $api->hosts();
		} catch ( \Exception $ex ) {
			$details = array(
				'error_message' => 'Can\'t authenticate: ' . $ex->getMessage()
			);
			include  W3TC_DIR . '/Cdn_Highwinds_Popup_View_Intro.php';
			exit();
		}

		$details = array(
			'account_hash' => $account_hash,
			'api_token' => $api_token,
			'hosts' => $hosts_response['list']
		);

		include  W3TC_DIR . '/Cdn_Highwinds_Popup_View_SelectHost.php';
		exit();
	}



	public function w3tc_ajax_cdn_highwinds_configure_host() {
		$account_hash = Util_Request::get_string( 'account_hash' );
		$api_token = Util_Request::get_string( 'api_token' );

		$host = Util_Request::get( 'host', '' );

		$details = array(
			'account_hash' => $account_hash,
			'api_token' => $api_token
		);

		$api = new Cdn_Highwinds_Api( $account_hash, $api_token );

		try {
			if ( empty( $host ) ) {
				$host = $this->_create_host( $api, Util_Request::get_string( 'host_new' ) );
			}
		} catch ( \Exception $ex ) {
			$api_hosts = $api->hosts();
			$details['hosts'] = $api_hosts['list'];
			$details['error_message'] = $ex->getMessage();
			include  W3TC_DIR . '/Cdn_Highwinds_Popup_View_SelectHost.php';
			exit();
		}

		// try to obtain CNAMEs
		$c = Dispatcher::config();
		try {
			$scopes_response = $api->configure_scopes( $host );
			$scope_id = 0;

			foreach ( $scopes_response['list'] as $scope ) {
				if ( $scope['platform'] == 'CDS' )
					$scope_id = $scope['id'];
			}

			if ( $scope_id <= 0 )
				throw new Exception( 'scope CDN hasnt been created' );

			$configuration = $api->configure_scope_get( $host, $scope_id );
			if ( isset( $configuration['hostname'] ) ) {
				$domains = array();
				foreach ( $configuration['hostname'] as $d )
					$domains[] = $d['domain'];

				$c->set( 'cdn.highwinds.host.domains', $domains );
			}
		} catch ( \Exception $ex ) {
		}

		$c->set( 'cdn.highwinds.account_hash', $account_hash );
		$c->set( 'cdn.highwinds.api_token', $api_token );
		$c->set( 'cdn.highwinds.host.hash_code', $host );
		$c->save();

		$postfix = Util_Admin::custom_message_id( array(),
			array(
				'cdn_configuration_saved' =>
				'CDN credentials are saved successfully' ) );
		echo 'Location admin.php?page=w3tc_cdn&' . esc_html( $postfix );
		exit();
	}



	private function _create_host( $api, $host_name ) {
		// create simple host
		$services_response = $api->services();

		// select all CDS services since its going to use caching
		$service_ids = array();
		foreach ( $services_response['list'] as $s ) {
			if ( strpos( $s['name'], 'CDS' ) >= 0 )
				$service_ids[] = $s['id'];
		}

		$origins_response = $api->origins();
		$home_domain = Util_Environment::home_url_host();
		$origin_id = 0;
		foreach ( $origins_response['list'] as $o ) {
			if ( $o['hostname'] == $home_domain ) {
				$origin_id = $o['id'];
				break;
			}
		}

		if ( $origin_id == 0 ) {
			try {
				$name = preg_replace( '/[^0-9a-z]/', '_', $home_domain );

				$origin_response = $api->origin_add( array(
						'name' => $name,
						'hostname' => $home_domain,
						'path' => '/',
						'port' => 80
					) );

				$origin_id = $origin_response['id'];
			} catch ( \Exception $ex ) {
				throw new \Exception( 'Can\'t create origin ' . $home_domain . ': ' .
					$ex->getMessage() );
			}
		}

		try {
			// create host
			$host_response = $api->host_add( array(
					'name' => Util_Request::get_string( 'host_new' ),
					'services' => $service_ids
				) );
			$host = $host_response['hashCode'];
		} catch ( \Exception $ex ) {
			throw new \Exception( 'Can\'t create new host: ' . $ex->getMessage() );
		}


		// configure host
		$scopes_response = $api->configure_scopes( $host );
		$scope_id = 0;

		foreach ( $scopes_response['list'] as $scope ) {
			if ( $scope['platform'] == 'CDS' )
				$scope_id = $scope['id'];
		}

		if ( $scope_id <= 0 )
			throw new Exception( 'Cant\'t configure host - scope CDN hasnt been created' );

		$configuration = $api->configure_scope_get( $host, $scope_id );

		// apply usually optimal default values
		$configuration['cacheControl'] = array( array( 'maxAge' => 31536000 ) );
		$configuration['compression'] = array( 'gzip' => 'css,js' );
		$configuration['originPullCacheExtension'] = array(
			'expiredCacheExtension' => 86400 );
		$configuration['originPullHost'] = array( 'primary' => $origin_id );
		$configuration['originPullPolicy'] = array( array(
				'expirePolicy' => 'CACHE_CONTROL',
				'expireSeconds' => 86400,
				'httpHeaders' => 'Access-Control-Allow-Origin'
			) );

		try {
			$configuration_response = $api->configure_scope_set( $host,
				$scope_id, $configuration );
		} catch ( \Exception $ex ) {
			throw new \Exception( 'Cant\'t configure host: ' . $ex->getMessage() );
		}

		return $host;
	}



	public function w3tc_ajax_cdn_highwinds_configure_cnames_form() {
		$this->render_configure_cnames_form();
		exit();
	}



	public function w3tc_ajax_cdn_highwinds_configure_cnames() {
		$details = array(
			'cnames' => Util_Request::get_array( 'cdn_cnames' )
		);

		$core = Dispatcher::component( 'Cdn_Core' );
		$cdn = $core->get_cdn();

		try {
			// try to obtain CNAMEs
			$cdn->service_cnames_set( $details['cnames'] );

			$c = Dispatcher::config();
			$c->set( 'cdn.highwinds.host.domains', $details['cnames'] );
			$c->save();

			$postfix = Util_Admin::custom_message_id( array(),
				array( 'cdn_cnames_saved' => 'CNAMEs are saved successfully' ) );
			echo 'Location admin.php?page=w3tc_cdn&' . esc_html( $postfix );
			exit();
		} catch ( \Exception $ex ) {
			$details['error_message'] = $ex->getMessage();
		}

		$this->render_configure_cnames_form( $details );
		exit();
	}



	private function render_configure_cnames_form( $details = array() ) {
		if ( isset( $details['cnames'] ) )
			$cnames = $details['cnames'];
		else {
			$core = Dispatcher::component( 'Cdn_Core' );
			$cdn = $core->get_cdn();

			try {
				// try to obtain CNAMEs
				$cnames = $cdn->service_cnames_get();
			} catch ( \Exception $ex ) {
				$details['error_message'] = $ex->getMessage();
				$cnames = array();
			}
		}

		include  W3TC_DIR . '/Cdn_Highwinds_Popup_View_ConfigureCnamesForm.php';
	}
}
