<?php
namespace W3TC;



class Extension_CloudFlare_AdminActions {
	public function w3tc_cloudflare_flush() {
		$c = Dispatcher::config();
		$api = new Extension_CloudFlare_Api( array(
				'email' => $c->get_string( array( 'cloudflare', 'email' ) ),
				'key' => $c->get_string( array( 'cloudflare', 'key' ) ),
				'zone_id' => $c->get_string( array( 'cloudflare', 'zone_id' ) ),
				'timelimit_api_request' => $c->get_integer(
					array( 'cloudflare', 'timelimit.api_request' ) )
			)
		);

		try {
			$v = $api->purge();
		} catch ( \Exception $ex ) {
			Util_Admin::redirect_with_custom_messages2( array(
					'errors' => array(
						'cloudflare_flush' =>
						__( 'Failed to purge CloudFlare cache: ', 'w3-total-cache' ) .
						$ex->getMessage()
					)
				) );
			return;
		}

		Util_Admin::redirect_with_custom_messages2( array(
				'notes' => array(
					'cloudflare_flush' => __( 'CloudFlare cache successfully emptied.', 'w3-total-cache' )
				)
			) );
	}



	/**
	 * Flush all caches except CloudFlare action
	 *
	 * @return void
	 */
	public function w3tc_cloudflare_flush_all_except_cf() {
		Dispatcher::component( 'CacheFlush' )->flush_all( array(
				'cloudflare' => 'skip' ) );

		Util_Admin::redirect( array(
				'w3tc_note' => 'flush_all'
			), true );
	}



	public function w3tc_cloudflare_save_settings() {
		$api = Extension_CloudFlare_SettingsForUi::api();
		$errors = Extension_CloudFlare_SettingsForUi::settings_set( $api );

		if ( empty( $errors ) ) {
			Util_Admin::redirect_with_custom_messages2( array(
					'notes' => array(
						'cloudflare_save_done' =>
						__( 'CloudFlare settings are successfully updated.',
							'w3-total-cache' )
					)
				) );
		} else {
			Util_Admin::redirect_with_custom_messages2( array(
					'errors' => array(
						'cloudflare_save_error' =>
						__( 'Failed to update CloudFlare settings:',
							'w3-total-cache' ) .
						"<br />\n" .
						implode( "<br />\n", $errors )
					)
				) );
		}
	}
}
