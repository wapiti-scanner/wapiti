<?php
namespace W3TC;



class Cdnfsd_StackPath_Popup {
	static public function w3tc_ajax() {
		$o = new Cdnfsd_StackPath_Popup();

		add_action( 'w3tc_ajax_cdn_stackpath_fsd_intro',
			array( $o, 'w3tc_ajax_cdn_stackpath_fsd_intro' ) );
		add_action( 'w3tc_ajax_cdn_stackpath_fsd_list_zones',
			array( $o, 'w3tc_ajax_cdn_stackpath_fsd_list_zones' ) );
		add_action( 'w3tc_ajax_cdn_stackpath_fsd_view_zone',
			array( $o, 'w3tc_ajax_cdn_stackpath_fsd_view_zone' ) );
		add_action( 'w3tc_ajax_cdn_stackpath_fsd_configure_zone',
			array( $o, 'w3tc_ajax_cdn_stackpath_fsd_configure_zone' ) );
		add_action( 'w3tc_ajax_cdn_stackpath_fsd_configure_zone_skip',
			array( $o, 'w3tc_ajax_cdn_stackpath_fsd_configure_zone_skip' ) );
	}



	public function w3tc_ajax_cdn_stackpath_fsd_intro() {
		$config = Dispatcher::config();

		$this->render_intro( array(
				'api_key' => $config->get_string( 'cdnfsd.stackpath.api_key' ) ) );
	}



	private function render_intro( $details ) {
		$config = Dispatcher::config();
		$url_obtain_key = W3TC_STACKPATH_AUTHORIZE_URL;

		include  W3TC_DIR . '/Cdnfsd_StackPath_Popup_View_Intro.php';
		exit();
	}



	public function w3tc_ajax_cdn_stackpath_fsd_list_zones() {
		$api_key = Util_Request::get_string( 'api_key' );

		$api = Cdn_StackPath_Api::create( $api_key );
		if ( !$api->is_valid() ) {
			$this->render_intro( array(
					'api_key' => $api_key,
					'error_message' => 'Can\'t authenticate: API key not valid'
				) );
			exit();
		}

		try {
			$zones = $api->get_sites();
		} catch ( \Exception $ex ) {
			$error_message = 'Can\'t authenticate: ' . $ex->getMessage();

			if ( strpos( $error_message, 'not whitelisted' ) > 0 ) {
				$error_message .= '. You can whitelist IP ' .
					'<a target="_blank" href="https://app.stackpath.com/account/api/whitelist">here</a>';
			}
			$this->render_intro( array(
					'api_key' => $api_key,
					'error_message' => $error_message
				) );
			exit();
		}

		$details = array(
			'api_key' => $api_key,
			'zones' => $zones
		);

		include  W3TC_DIR . '/Cdnfsd_StackPath_Popup_View_Zones.php';
		exit();
	}



	public function w3tc_ajax_cdn_stackpath_fsd_view_zone() {
		$api_key = Util_Request::get_string( 'api_key' );
		$zone_id = Util_Request::get( 'zone_id', '' );

		$details = array(
			'api_key' => $api_key,
			'zone_id' => $zone_id,
			'name' => '',
			'url' => array(
				'new' => get_home_url() ),
			'ip' => array(),
			// needs to be off since original DNS will be replaced with stackpath's
			'dns_check' => array(
				'new' => 0
			),
			// needs to be off, since WP issues no-cache headers for wp-admin
			// and logged-in users
			'ignore_cache_control' => array(
				'new' => 0
			),
			'custom_domain' => array(
				'new' => Util_Environment::home_url_host()
			)
		);

		if ( empty( $zone_id ) ) {
			// create new zone mode
			$details['name'] = Util_Request::get( 'zone_new_name' );
			$details['ip']['new'] = Cdnfsd_Util::get_suggested_home_ip();
		} else {
			$api = Cdn_StackPath_Api::create( $api_key );
			try {
				$zone = $api->get_site( $zone_id );
				$custom_domains = $api->get_custom_domains( $zone_id );
			} catch ( \Exception $ex ) {
				$this->render_intro( array(
						'api_key' => $api_key,
						'error_message' => 'Can\'t obtain zone: ' . $ex->getMessage()
					) );
				exit();
			}

			$details['custom_domain']['current'] = '';

			foreach ( $custom_domains as $d ) {
				$details['custom_domain']['current'] = $d;
				if ( $d == Util_Environment::home_url_host() )
					break;
			}

			$details['name'] = $zone['name'];
			$details['dns_check']['current'] = $zone['dns_check'];
			$details['ignore_cache_control'] = $zone['ignore_cache_control'];
			$details['url']['current'] = $zone['url'];
			$details['ip']['current'] = $zone['ip'];

			$origin_ip = Cdnfsd_Util::get_suggested_home_ip();
			$cdn_ip = gethostbyname( $zone['tmp_url'] );

			if ( $origin_ip != $cdn_ip )
				$details['ip']['new'] = $origin_ip;
		}



		include  W3TC_DIR . '/Cdnfsd_StackPath_Popup_View_Zone.php';
		exit();
	}



	private function render_zone_value_change( $details, $field ) {
		Util_Ui::hidden( '', $field, $details[$field]['new'] );

		if ( !isset( $details[$field]['current'] ) ||
			$details[$field]['current'] == $details[$field]['new'] )
			echo esc_html( $details[ $field ]['new'] );
		else {
			echo 'currently set to <strong>' .
				esc_html( empty( $details[ $field ]['current'] ) ?
				'<empty>' : $details[$field]['current'] ) .
				'</strong><br />';
			echo 'will be changed to <strong>' .
				esc_html( $details[ $field ]['new'] ) . '</strong><br />';
		}
	}



	private function render_zone_boolean_change( $details, $field ) {
		Util_Ui::hidden( '', $field, $details[$field]['new'] );

		if ( !isset( $details[$field]['current'] ) ) {
			echo 'will be set to <strong>';
			echo esc_html( $this->render_zone_boolean( $details[ $field ]['new'] ) );
			echo '</strong>';
		} else if ( $details[$field]['current'] == $details[$field]['new'] ) {
				echo '<strong>';
				echo esc_html( $this->render_zone_boolean( $details[ $field ]['new'] ) );
				echo '</strong>';
			} else {
			echo 'currently set to <strong>';
			$this->render_zone_boolean( $details[$field]['current'] );
			echo '</strong><br />';
			echo 'will be changed to <strong>';
			$this->render_zone_boolean( $details[$field]['new'] );
			echo '</strong><br />';
		}
	}



	private function render_zone_boolean( $v ) {
		if ( $v == 0 )
			echo 'disabled';
		else
			echo 'enabled';
	}



	private function render_zone_ip_change( $details, $field ) {
		Util_Ui::textbox( '', $field, $details[$field]['new'] );

		if ( isset( $details[$field]['current'] ) &&
			$details[$field]['current'] != $details[$field]['new'] ) {
			echo '<p class="description">currently set to <strong>' .
				esc_html( $details[ $field ]['current'] ) . '</strong></p>';
		}
	}



	public function w3tc_ajax_cdn_stackpath_fsd_configure_zone() {
		$api_key = Util_Request::get_string( 'api_key' );
		$zone_id = Util_Request::get( 'zone_id', '' );

		$zone = array(
			'name' => Util_Request::get( 'name' ),
			'label' => Util_Request::get( 'name' ),
			'url' => Util_Request::get( 'url' ),
			'use_stale' => 1,
			'queries' => 1,
			'compress' => 1,
			'backend_compress' => 1,
			'dns_check' => Util_Request::get( 'dns_check' ),
			'ip' => Util_Request::get( 'ip' )
		);

		if ( empty( $zone['ip'] ) ) {
			unset( $zone['ip'] );
		}

		$api = Cdn_StackPath_Api::create( $api_key );

		try {
			if ( empty( $zone_id ) ) {
				$response = $api->create_site( $zone );
				$zone_id = $response['id'];
			} else {
				$response = $api->update_site( $zone_id, $zone );
			}

			$custom_domains = $api->get_custom_domains( $zone_id );
			$custom_domain = Util_Request::get( 'custom_domain' );

			$added = false;
			foreach ( $custom_domains as $d ) {
				if ( $d == $custom_domain ) {
					$added = true;
					break;
				}
			}
			if ( !$added ) {
				$api->create_custom_domain( $zone_id, $custom_domain );
			}
		} catch ( \Exception $ex ) {
			$this->render_intro( array(
					'api_key' => $api_key,
					'error_message' => 'Failed to configure custom domain ' . $custom_domain . ': ' . $ex->getMessage()
				) );
			exit();
		}

		$zone_domain = $response['tmp_url'];

		$c = Dispatcher::config();
		$c->set( 'cdnfsd.stackpath.api_key', $api_key );
		$c->set( 'cdnfsd.stackpath.zone_id', $zone_id );
		$c->set( 'cdnfsd.stackpath.zone_domain', $zone_domain );
		$c->save();

		$details = array(
			'name' => $zone['name'],
			'home_domain' => Util_Environment::home_url_host(),
			'dns_cname_target' => $zone_domain,
		);

		include  W3TC_DIR . '/Cdnfsd_StackPath_Popup_View_Success.php';
		exit();
	}



	public function w3tc_ajax_cdn_stackpath_fsd_configure_zone_skip() {
		$api_key = Util_Request::get_string( 'api_key' );
		$zone_id = Util_Request::get( 'zone_id', '' );

		$api = Cdn_StackPath_Api::create( $api_key );

		try {
			$zone = $api->get_site( $zone_id );
		} catch ( \Exception $ex ) {
			$this->render_intro( array(
					'api_key' => $api_key,
					'error_message' => 'Failed to obtain custom domains: ' . $ex->getMessage()
				) );
			exit();
		}

		$zone_domain = $zone['cdn_url'];

		$c = Dispatcher::config();
		$c->set( 'cdnfsd.stackpath.api_key', $api_key );
		$c->set( 'cdnfsd.stackpath.zone_id', $zone_id );
		$c->set( 'cdnfsd.stackpath.zone_domain', $zone_domain );
		$c->save();

		$details = array(
			'name' => $zone['name'],
			'home_domain' => Util_Environment::home_url_host(),
			'dns_cname_target' => $zone_domain,
		);

		include  W3TC_DIR . '/Cdnfsd_StackPath_Popup_View_Success.php';
		exit();
	}
}
