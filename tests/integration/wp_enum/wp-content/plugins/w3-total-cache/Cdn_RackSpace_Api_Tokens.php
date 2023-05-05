<?php
namespace W3TC;



class Cdn_RackSpace_Api_Tokens {
	static public function authenticate( $user_name, $api_key ) {
		$request_json = array( 'auth' =>
			array( 'RAX-KSKEY:apiKeyCredentials' => array(
					'username' => $user_name,
					'apiKey' => $api_key
				) ) );

		$result = wp_remote_post(
			'https://identity.api.rackspacecloud.com/v2.0/tokens',
			array(
				'headers' => array(
					'Accept' => 'application/json',
					'Content-Type' => 'application/json'
				),
				//'sslcertificates' => dirname( __FILE__ ) .
				//'/Cdn_RackSpace_Api_CaCert.pem',
				'body' => json_encode( $request_json )
			)
		);

		$response = self::_decode_response( $result );
		if ( !isset( $response['access'] ) )
			throw new \Exception(
				'Unexpected authentication response: access token not found' );

		$r = $response['access'];

		// fill service descriptors by region

		if ( !isset( $r['serviceCatalog'] ) )
			throw new \Exception(
				'Unexpected authentication response: serviceCatalog token not found' );
		$services = $r['serviceCatalog'];

		return array(
			'access_token' => $r['token']['id'],
			'services' => $services
		);
	}



	static public function cloudfiles_services_by_region( $services ) {
		$by_region = array();

		foreach ( $services as $s ) {
			if ( $s['type'] == 'object-store' ) {
				foreach ( $s['endpoints'] as $endpoint ) {
					$region = $endpoint['region'];
					if ( !isset( $by_region[$region] ) )
						$by_region[$region] = array();

					$by_region[$region]['object-store.publicURL'] =
						$endpoint["publicURL"];
					$by_region[$region]['object-store.internalURL'] =
						$endpoint["internalURL"];
				}
			} elseif ( $s['type'] == 'rax:object-cdn' ) {
				foreach ( $s['endpoints'] as $endpoint ) {
					$region = $endpoint['region'];
					if ( !isset( $by_region[$region] ) )
						$by_region[$region] = array();

					$by_region[$region]['object-cdn.publicURL'] =
						$endpoint["publicURL"];
				}
			}
		}

		$by_region = self::_add_region_names( $by_region );
		return $by_region;
	}



	static public function cdn_services_by_region( $services ) {
		$by_region = array();

		foreach ( $services as $s ) {
			if ( $s['type'] == 'rax:cdn' ) {
				foreach ( $s['endpoints'] as $endpoint ) {
					$region = $endpoint['region'];
					if ( !isset( $by_region[$region] ) )
						$by_region[$region] = array();

					$by_region[$region]['cdn.publicURL'] =
						$endpoint["publicURL"];
				}
			}
		}

		$by_region = self::_add_region_names( $by_region );
		return $by_region;
	}



	static private function _add_region_names( $by_region ) {
		// try to decode region names
		$region_names = array(
			'ORD' => 'Chicago (ORD)',
			'DFW' => 'Dallas/Ft. Worth (DFW)',
			'HKG' => 'Hong Kong (HKG)',
			'LON' => 'London (LON)',
			'IAD' => 'Northern Virginia (IAD)',
			'SYD' => 'Sydney (SYD)'
		);

		$keys = array_keys( $by_region );
		foreach ( $keys as $region ) {
			if ( isset( $region_names[$region] ) )
				$by_region[$region]['name'] = $region_names[$region];
			else
				$by_region[$region]['name'] = $region;
		}

		return $by_region;
	}



	static private function _decode_response( $result ) {
		if ( is_wp_error( $result ) )
			throw new \Exception( 'Failed to reach API endpoint' );

		$response_json = @json_decode( $result['body'], true );
		if ( is_null( $response_json ) )
			throw new \Exception(
				'Failed to reach API endpoint, got unexpected response ' .
				$result['body'] );
		if ( isset( $response_json['unauthorized']['message'] ) )
			throw new \Exception( $response_json['unauthorized']['message'] );

		if ( $result['response']['code'] != '200' && $result['response']['code'] != '201' )
			throw new \Exception( $result['body'] );

		return $response_json;
	}
}
