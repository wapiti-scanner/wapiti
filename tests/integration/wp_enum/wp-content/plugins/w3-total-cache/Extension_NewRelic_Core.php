<?php
namespace W3TC;

class Extension_NewRelic_Core {
	public function get_effective_browser_application() {
		$c = Dispatcher::config();
		$api_key = $c->get( array( 'newrelic', 'api_key' ) );
		$id = $c->get( array( 'newrelic', 'browser.application_id' ) );

		if ( empty( $api_key ) || empty( $id ) )
			return null;

		$applications_string = get_option( 'w3tc_nr_browser_applications' );
		$applications = @json_decode( $applications_string, true );
		if ( !is_array( $applications ) )
			$applications = array();

		if ( isset( $applications[$id] ) )
			return $applications[$id];

		try {
			$api = new Extension_NewRelic_Api( $api_key );
			$app = $api->get_browser_application( $id );

			if ( !is_null( $app ) ) {
				$applications[$id] = $app;
				update_option( 'w3tc_nr_browser_applications',
					json_encode( $applications ) );
			}

			return $app;
		} catch ( \Exception $ex ) {
			return null;
		}
	}
}
