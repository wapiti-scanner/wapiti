<?php
namespace W3TC;

class Extension_CloudFlare_SettingsForUi {
	static public function api() {
		$c = Dispatcher::config();
		$api = new Extension_CloudFlare_Api( array(
				'email' => $c->get_string( array( 'cloudflare', 'email' ) ),
				'key' => $c->get_string( array( 'cloudflare', 'key' ) ),
				'zone_id' => $c->get_string( array( 'cloudflare', 'zone_id' ) ),
				'timelimit_api_request' => $c->get_integer(
					array( 'cloudflare', 'timelimit.api_request' ) )
			)
		);

		return $api;
	}


	static public function settings_get( $api ) {
		$settings = $api->zone_settings();

		// adjust settings that are out of regular presentation
		if ( isset( $settings['security_header'] ) ) {
			$v = $settings['security_header']['value'];

			$settings['security_header']['editable'] = false;
			$settings['security_header']['value'] = 'off';
			if ( isset( $v['strict_transport_security']['enabled'] ) ) {
				$settings['security_header']['value'] =
					$v['strict_transport_security']['enabled'] ?
					'on' : 'off';
			}
		}
		if ( isset( $settings['mobile_redirect'] ) ) {
			$v = $settings['mobile_redirect']['value'];

			$settings['mobile_redirect']['editable'] = false;
			$settings['mobile_redirect']['value'] = 'off';
			if ( isset( $v['status'] ) ) {
				$settings['mobile_redirect']['value'] =
					$v['status'] ? 'on' : 'off';
			}
		}
		if ( isset( $settings['minify'] ) ) {
			$v = $settings['minify']['value'];

			$editable = $settings['minify']['editable'];
			$settings['minify_js'] = array(
				'editable' => $editable,
				'value' => $v['js']
			);
			$settings['minify_css'] = array(
				'editable' => $editable,
				'value' => $v['css']
			);
			$settings['minify_html'] = array(
				'editable' => $editable,
				'value' => $v['html']
			);
		}

		return $settings;
	}



	/**
	 * Updates settings passed by $_REQUEST
	 */
	static public function settings_set( $api ) {
		$errors = array();
		$settings = self::settings_get( $api );
		$to_update = array();

		$prefix = 'cloudflare_api_';
		foreach ( $_REQUEST as $key => $value ) {
			if ( substr( $key, 0, strlen( $prefix ) ) != $prefix )
				continue;
			if ( $value == '' )
				continue;

			$value = Util_Request::get_string( $key );

			$settings_key = substr( $key, strlen( $prefix ) );

			if ( !isset( $settings[$settings_key] ) ) {
				$errors[] = 'Option ' . $settings_key . ' is not available';
				continue;
			}

			$current_value = $settings[$settings_key]['value'];

			// convert checkbox value to on/off
			// exception: rocket loader, ssl is not checkbox so contains real value
			if ( $settings_key != 'rocket_loader' && $settings_key != 'ssl' ) {
				if ( $current_value == 'on' || $current_value == 'off' ) {
					// it's boolean, so control is checkbox - convert it
					$value = ( $value == '0' ? 'off' : 'on' );
				}
			}

			if ( $current_value == $value )
				continue;   // no update required

			if ( !$settings[$settings_key]['editable'] ) {
				$errors[] = 'Option ' . $settings_key . ' is read-only';
				continue;
			}

			$to_update[$settings_key] = $value;
		}

		// mutate settings back to the format of API
		if ( isset( $to_update['minify_js'] ) ||
			isset( $to_update['minify_css'] ) ||
			isset( $to_update['minify_html'] ) ) {
			$v = $settings['minify']['value'];
			if ( isset( $to_update['minify_js'] ) ) {
				$v['js'] = $to_update['minify_js'];
				unset( $to_update['minify_js'] );
			}
			if ( isset( $to_update['minify_css'] ) ) {
				$v['css'] = $to_update['minify_css'];
				unset( $to_update['minify_css'] );
			}
			if ( isset( $to_update['minify_html'] ) ) {
				$v['html'] = $to_update['minify_html'];
				unset( $to_update['minify_html'] );
			}

			$to_update['minify'] = $v;
		}

		// do the settings update via API
		foreach ( $to_update as $key => $value ) {
			try {
				$api->zone_setting_set( $key, $value );
			} catch ( \Exception $ex ) {
				$errors[] = 'Failed to update option ' . $key . ': ' .
					$ex->getMessage();
			}
		}

		return $errors;
	}
}
