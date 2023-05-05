<?php
namespace W3TC;

class Cdn_RackSpaceCdn_Popup {
	public static function w3tc_ajax() {
		$o = new Cdn_RackSpaceCdn_Popup();

		add_action( 'w3tc_ajax_cdn_rackspace_intro', array( $o, 'w3tc_ajax_cdn_rackspace_intro' ) );
		add_action( 'w3tc_ajax_cdn_rackspace_intro_done', array( $o, 'w3tc_ajax_cdn_rackspace_intro_done' ) );
		add_action( 'w3tc_ajax_cdn_rackspace_regions_done', array( $o, 'w3tc_ajax_cdn_rackspace_regions_done' ) );
		add_action( 'w3tc_ajax_cdn_rackspace_services_done', array( $o, 'w3tc_ajax_cdn_rackspace_services_done' ) );
		add_action( 'w3tc_ajax_cdn_rackspace_service_create_done', array( $o, 'w3tc_ajax_cdn_rackspace_service_create_done' ) );
		add_action( 'w3tc_ajax_cdn_rackspace_service_get_state', array( $o, 'w3tc_ajax_cdn_rackspace_service_get_state' ) );
		add_action( 'w3tc_ajax_cdn_rackspace_service_created_done', array( $o, 'w3tc_ajax_cdn_rackspace_service_created_done' ) );
		add_action( 'w3tc_ajax_cdn_rackspace_service_actualize_done', array( $o, 'w3tc_ajax_cdn_rackspace_service_actualize_done' ) );
		add_action( 'w3tc_ajax_cdn_rackspace_configure_domains', array( $o, 'w3tc_ajax_cdn_rackspace_configure_domains' ) );
		add_action( 'w3tc_ajax_cdn_rackspace_configure_domains_done', array( $o, 'w3tc_ajax_cdn_rackspace_configure_domains_done' ) );
	}

	public function w3tc_ajax_cdn_rackspace_intro() {
		$c = Dispatcher::config();

		$details = array(
			'user_name' => $c->get_string( 'cdn.rackspace_cdn.user_name' ),
			'api_key'   => $c->get_string( 'cdn.rackspace_cdn.api_key' ),
		);

		include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_Intro.php';
		exit();
	}

	public function w3tc_ajax_cdn_rackspace_intro_done() {
		$this->_render_cdn_rackspace_regions(
			array(
				'user_name' => Util_Request::get_string( 'user_name' ),
				'api_key' => Util_Request::get_string( 'api_key' ),
			)
		);
	}

	private function _render_cdn_rackspace_regions( $details ) {
		$user_name = $details['user_name'];
		$api_key   = $details['api_key'];

		try {
			$r = Cdn_RackSpace_Api_Tokens::authenticate( $user_name, $api_key );
		} catch ( \Exception $ex ) {
			$details = array(
				'user_name'     => $user_name,
				'api_key'       => $api_key,
				'error_message' => 'Can\'t authenticate: ' . $ex->getMessage(),
			);
			include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_Intro.php';
			exit();
		}

		$r['regions'] = Cdn_RackSpace_Api_Tokens::cdn_services_by_region( $r['services'] );

		$details['access_token']       = $r['access_token'];
		$details['region_descriptors'] = $r['regions'];

		// avoid fights with quotes, magic_quotes may break randomly.
		$details['region_descriptors_serialized'] = strtr( wp_json_encode( $r['regions'] ), '"\\', '!^' );

		include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_Regions.php';
		exit();
	}

	public function w3tc_ajax_cdn_rackspace_regions_done() {
		$user_name          = Util_Request::get_string( 'user_name' );
		$api_key            = Util_Request::get_string( 'api_key' );
		$access_token       = Util_Request::get_string( 'access_token' );
		$region             = Util_Request::get_string( 'region' );
		$region_descriptors = json_decode(
			strtr( Util_Request::get_string( 'region_descriptors' ), '!^', '"\\' ),
			true
		);

		if ( ! isset( $region_descriptors[$region] ) ) {
			return $this->_render_cdn_rackspace_regions(
				array(
					'user_name'     => $user_name,
					'api_key'       => $api_key,
					'error_message' => 'Please select region ' . $region,
				)
			);
		}

		$api = new Cdn_RackSpace_Api_Cdn(
			array(
				'access_token'             => $access_token,
				'access_region_descriptor' => $region_descriptors[ $region ],
				'new_access_required'      => '',
			)
		);

		try {
			$services = $api->services();
		} catch ( \Exception $ex ) {
			$details = array(
				'user_name'     => $user_name,
				'api_key'       => $api_key,
				'error_message' => $ex->getMessage(),
			);
			include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_Intro.php';
			exit();
		}

		$details = array(
			'user_name'                           => $user_name,
			'api_key'                             => $api_key,
			'access_token'                        => $access_token,
			'access_region_descriptor_serialized' => strtr( wp_json_encode( $region_descriptors[ $region ] ), '"\\', '!^' ),
			'region'                              => $region,
			// avoid fights with quotes, magic_quotes may break randomly.
			'services'                            => $services,
		);

		include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_Services.php';
		exit();
	}

	public function w3tc_ajax_cdn_rackspace_services_done() {
		$user_name                = Util_Request::get_string( 'user_name' );
		$api_key                  = Util_Request::get_string( 'api_key' );
		$access_token             = Util_Request::get_string( 'access_token' );
		$access_region_descriptor = json_decode( strtr( Util_Request::get_string( 'access_region_descriptor' ), '!^', '"\\' ), true );
		$region                   = Util_Request::get_string( 'region' );
		$service                  = Util_Request::get( 'service' );

		if ( !empty( $service ) ) {
			$this->_render_service_actualize(
				array(
					'user_name'                           => $user_name,
					'api_key'                             => $api_key,
					'access_token'                        => $access_token,
					'access_region_descriptor_serialized' => strtr( json_encode( $access_region_descriptor ), '"\\', '!^' ),
					'region'                              => $region,
					'service_id'                          => $service,
				)
			);

			exit();
		}

		$home_url = get_home_url();
		$parsed   = wp_parse_url( $home_url );

		$is_https = ( 'https' === $parsed['scheme'] );

		$details = array(
			'user_name'                           => $user_name,
			'api_key'                             => $api_key,
			'access_token'                        => $access_token,
			'access_region_descriptor_serialized' => strtr( wp_json_encode( $access_region_descriptor ), '"\\', '!^' ),
			'region'                              => $region,
			'name'                                => '',
			'protocol'                            => ( $is_https ? 'https' : 'http' ),
			'cname_http'                          => '',
			'cname_http_style'                    => ( $is_https ? 'display: none' : '' ),
			'cname_https_prefix'                  => '',
			'cname_https_style'                   => ( $is_https ? '' : 'display: none' ),
			'origin'                              => Util_Environment::home_url_host(),
		);

		include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_Service_Create.php';
		exit();
	}

	public function w3tc_ajax_cdn_rackspace_service_create_done() {
		$user_name                = Util_Request::get_string( 'user_name' );
		$api_key                  = Util_Request::get_string( 'api_key' );
		$access_token             = Util_Request::get_string( 'access_token' );
		$access_region_descriptor = json_decode( strtr( Util_Request::get_string( 'access_region_descriptor' ), '!^', '"\\' ), true );
		$region                   = Util_Request::get_string( 'region' );
		$name                     = Util_Request::get_string( 'name' );
		$protocol                 = Util_Request::get_string( 'protocol' );
		$cname_http               = Util_Request::get_string( 'cname_http' );
		$cname_https_prefix       = Util_Request::get_string( 'cname_https_prefix' );
		$is_https                 = ( 'https' === $protocol );
		$cname                    = ( $is_https ? $cname_https_prefix : $cname_http );
		$api                      = new Cdn_RackSpace_Api_Cdn(
			array(
				'access_token'             => $access_token,
				'access_region_descriptor' => $access_region_descriptor,
				'new_access_required'      => '',
			)
		);
		$service_id               = null;
		$access_url               = null;

		try {
			$domain = array(
				'domain'   => $cname,
				'protocol' => ( $is_https ? 'https' : 'http' ),
			);

			if ( $is_https ) {
				$domain['certificate'] = 'shared';
			}

			$service_id = $api->service_create(
				array(
					'name'    => $name,
					'domains' => array( $domain ),
					'origins' => array(
						array(
							'origin'         => Util_Environment::home_url_host(),
							'port'           => ( $is_https ? 443 : 80 ),
							'ssl'            => $is_https,
							'hostheadertype' => 'origin',
							'rules'          => array(),
						),
					),
					'caching' => array(
						array(
							'name' => 'default',
							'ttl'  => 86400,
						),
					),
				)
			);
		} catch ( \Exception $ex ) {
			$details = array(
				'user_name'                           => $user_name,
				'api_key'                             => $api_key,
				'access_token'                        => $access_token,
				'access_region_descriptor_serialized' => strtr( wp_json_encode( $access_region_descriptor ), '"\\', '!^' ),
				'region'                              => $region,
				'name'                                => $name,
				'protocol'                            => ( $is_https ? 'https' : 'http' ),
				'cname_http'                          => $cname_http,
				'cname_http_style'                    => ( $is_https ? 'display: none' : '' ),
				'cname_https_prefix'                  => $cname_https_prefix,
				'cname_https_style'                   => ( $is_https ? '' : 'display: none' ),
				'origin'                              => Util_Environment::home_url_host(),
				'error_message'                       => $ex->getMessage(),
			);

			include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_Service_Create.php';
			exit();
		}

		$details = array(
			'user_name'                           => $user_name,
			'api_key'                             => $api_key,
			'access_token'                        => $access_token,
			'access_region_descriptor_serialized' => strtr( wp_json_encode( $access_region_descriptor ), '"\\', '!^' ),
			'region'                              => $region,
			'name'                                => $name,
			'is_https'                            => $is_https,
			'cname'                               => $cname,
			'service_id'                          => $service_id,
		);

		include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_Service_Created.php';
	}

	/**
	 * AJAX returning json for js-script about service state.
	 */
	public function w3tc_ajax_cdn_rackspace_service_get_state() {
		$access_token             = Util_Request::get_string( 'access_token' );
		$access_region_descriptor = json_decode( strtr( Util_Request::get_string( 'access_region_descriptor' ), '!^', '"\\' ), true );
		$service_id               = Util_Request::get_string( 'service_id' );
		$api                      = new Cdn_RackSpace_Api_Cdn(
			array(
				'access_token'             => $access_token,
				'access_region_descriptor' => $access_region_descriptor,
				'new_access_required'      => '',
			)
		);
		$service                  = $api->service_get( $service_id );
		$response                 = array( 'status' => 'Unknown' );

		if ( isset( $service['status'] ) ) {
			$response['status'] = $service['status'];
		}

		if ( isset( $service['links_by_rel']['access_url'] ) ) {
			$response['access_url'] = $service['links_by_rel']['access_url']['href'];
		}

		if ( isset( $service['domains'] ) ) {
			$response['cname'] = $service['domains'][0]['domain'];
		}

		// decode to friendly name.
		if ( 'create_in_progress' === $response['status'] ) {
			$response['status'] = 'Creation in progress...';
		}

		echo esc_html( wp_json_encode( $response ) );
	}

	public function w3tc_ajax_cdn_rackspace_service_created_done() {
		$this->_save_config();
	}

	private function _render_service_actualize( $details ) {
		$access_region_descriptor = json_decode( strtr( $details['access_region_descriptor_serialized'], '!^', '"\\' ), true );

		$api = new Cdn_RackSpace_Api_Cdn(
			array(
				'access_token'             => $details['access_token'],
				'access_region_descriptor' => $access_region_descriptor,
				'new_access_required'      => '',
			)
		);

		$service = null;
		try {
			$service = $api->service_get( $details['service_id'] );
		} catch ( \Exception $ex ) {
			$details['error_message'] = $ex->getMessage();
			include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_Intro.php';
			exit();
		}

		$origin   = '';
		$protocol = 'http';
		if ( isset( $service['origins'] ) && $service['origins'][0]['origin'] ) {
			$protocol = $service['origins'][0]['ssl'] ? 'https' : 'http';
			$origin   = $service['origins'][0]['origin'];
		}

		$details['name']     = $service['name'];
		$details['protocol'] = $protocol;
		$details['origin']   = array(
			'current' => $origin,
			'new'     => Util_Environment::home_url_host(),
		);

		include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_Service_Actualize.php';
		exit();
	}

	public function w3tc_ajax_cdn_rackspace_service_actualize_done() {
		$user_name                = Util_Request::get_string( 'user_name' );
		$api_key                  = Util_Request::get_string( 'api_key' );
		$access_token             = Util_Request::get_string( 'access_token' );
		$access_region_descriptor = json_decode( strtr( Util_Request::get_string( 'access_region_descriptor' ), '!^', '"\\' ), true );
		$region                   = Util_Request::get_string( 'region' );
		$service_id               = Util_Request::get_string( 'service_id' );
		$api                      = new Cdn_RackSpace_Api_Cdn(
			array(
				'access_token' => $access_token,
				'access_region_descriptor' => $access_region_descriptor,
				'new_access_required'      => '',
			)
		);

		try {
			$service = $api->service_get( $service_id );

			$is_https = false;
			$origin   = '';
			if ( isset( $service['origins'] ) && $service['origins'][0]['ssl'] ) {
				$is_https = $service['origins'][0]['ssl'];
				$origin   = $service['origins'][0]['origin'];
			}

			$new_origin = Util_Environment::home_url_host();
			if ( $origin !== $new_origin ) {
				$api->service_set(
					$service_id,
					array(
						array(
							'op'    => 'replace',
							'path'  => '/origins',
							'value' => array(
								array(
									'origin'         => $new_origin,
									'port'           => ( $is_https ? 443 : 80 ),
									'ssl'            => $is_https,
									'hostheadertype' => 'origin',
									'rules'          => array(),
								),
							),
						),
					)
				);
			}
		} catch ( \Exception $ex ) {
			$details = array(
				'user_name'     => $user_name,
				'api_key'       => $api_key,
				'error_message' => $ex->getMessage(),
			);
			include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_Intro.php';
			exit();
		}

		$this->_save_config();
	}

	private function _save_config() {
		$user_name                = Util_Request::get_string( 'user_name' );
		$api_key                  = Util_Request::get_string( 'api_key' );
		$access_token             = Util_Request::get_string( 'access_token' );
		$access_region_descriptor = json_decode( strtr( Util_Request::get_string( 'access_region_descriptor' ), '!^', '"\\' ), true );
		$region                   = Util_Request::get_string( 'region' );
		$service_id               = Util_Request::get_string( 'service_id' );
		$api                      = new Cdn_RackSpace_Api_Cdn(
			array(
				'access_token' => $access_token,
				'access_region_descriptor' => $access_region_descriptor,
				'new_access_required'      => '',
			)
		);
		$service                  = $api->service_get( $service_id );
		$access_url               = $service['links_by_rel']['access_url']['href'];
		$protocol                 = 'http';
		$domain                   = '';

		if ( isset( $service['domains'] ) && $service['domains'][0]['protocol'] ) {
			$protocol = $service['domains'][0]['protocol'];
			$domain   = $service['domains'][0]['domain'];
		}

		$c = Dispatcher::config();

		$c->set( 'cdn.rackspace_cdn.user_name', $user_name );
		$c->set( 'cdn.rackspace_cdn.api_key', $api_key );
		$c->set( 'cdn.rackspace_cdn.region', $region );
		$c->set( 'cdn.rackspace_cdn.service.name', $service['name'] );
		$c->set( 'cdn.rackspace_cdn.service.id', $service_id );
		$c->set( 'cdn.rackspace_cdn.service.access_url', $access_url );
		$c->set( 'cdn.rackspace_cdn.service.protocol', $protocol );

		if ( 'https' !== $protocol ) {
			$c->set( 'cdn.rackspace_cdn.domains', array( $domain ) );
		}

		$c->save();

		// reset calculated state.
		$state = Dispatcher::config_state();
		$state->set( 'cdn.rackspace_cdn.access_state', '' );
		$state->save();

		$postfix = Util_Admin::custom_message_id(
			array(),
			array( 'cdn_configuration_saved' => 'CDN credentials are saved successfully' )
		);
		echo esc_url( 'Location admin.php?page=w3tc_cdn&' . $postfix );
		exit();
	}

	/**
	 * CNAMEs popup
	 */
	public function w3tc_ajax_cdn_rackspace_configure_domains() {
		$this->render_configure_domains_form();
		exit();
	}

	public function w3tc_ajax_cdn_rackspace_configure_domains_done() {
		$details = array(
			'cnames' => Util_Request::get_array( 'cdn_cnames' ),
		);

		$core = Dispatcher::component( 'Cdn_Core' );
		$cdn  = $core->get_cdn();

		try {
			// try to obtain CNAMEs.
			$cdn->service_domains_set( $details['cnames'] );

			$c = Dispatcher::config();
			$c->set( 'cdn.rackspace_cdn.domains', $details['cnames'] );
			$c->save();

			$postfix = Util_Admin::custom_message_id(
				array(),
				array( 'cdn_cnames_saved' => 'CNAMEs are saved successfully' )
			);
			echo esc_url( 'Location admin.php?page=w3tc_cdn&' . $postfix );
			exit();
		} catch ( \Exception $ex ) {
			$details['error_message'] = $ex->getMessage();
		}

		$this->render_configure_domains_form( $details );
		exit();
	}

	private function render_configure_domains_form( $details = array() ) {
		if ( isset( $details['cnames'] ) ) {
			$cnames = $details['cnames'];
		} else {
			$core = Dispatcher::component( 'Cdn_Core' );
			$cdn  = $core->get_cdn();

			try {
				// try to obtain CNAMEs.
				$cnames = $cdn->service_domains_get();
			} catch ( \Exception $ex ) {
				$details['error_message'] = $ex->getMessage();
				$cnames                   = array();
			}
		}

		include W3TC_DIR . '/Cdn_RackSpaceCdn_Popup_View_ConfigureDomains.php';
	}

	private function render_service_value_change( $details, $field ) {
		Util_Ui::hidden( '', $field, $details[ $field ]['new'] );

		if ( ! isset( $details[ $field ]['current'] ) || $details[ $field ]['current'] === $details[ $field ]['new'] ) {
			echo esc_html( $details[ $field ]['new'] );
		} else {
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML strong tag, 2 current setting value, 3 closing HTML strong tag followed by HTML line break,
					// translators: 4 opening HTML strong tag, 5 new setting value, 6 closing HTML strong tag followed by HTML line break.
					__(
						'currently set to %1$s%2$s%3$s will be changed to %4$s%5$s%6$s',
						'w3-total-cache'
					),
					'<strong>',
					empty( $details[ $field ]['current'] ) ? '<empty>' : $details[ $field ]['current'],
					'</strong><br />',
					'<strong>',
					$details[ $field ]['new'],
					'</strong><br />'
				),
				array(
					'strong' => array(),
					'empty'  => array(),
					'br'     => array(),
				)
			);
		}
	}
}
