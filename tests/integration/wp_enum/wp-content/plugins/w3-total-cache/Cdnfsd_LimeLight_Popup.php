<?php
namespace W3TC;



class Cdnfsd_LimeLight_Popup {
	static public function w3tc_ajax() {
		$o = new Cdnfsd_LimeLight_Popup();

		add_action( 'w3tc_ajax_cdnfsd_limelight_intro',
			array( $o, 'w3tc_ajax_cdnfsd_limelight_intro' ) );
		add_action( 'w3tc_ajax_cdnfsd_limelight_save',
			array( $o, 'w3tc_ajax_cdnfsd_limelight_save' ) );
	}



	public function w3tc_ajax_cdnfsd_limelight_intro() {
		$this->render_intro( array() );
	}



	private function render_intro( $details ) {
		$config = Dispatcher::config();

		include  W3TC_DIR . '/Cdnfsd_LimeLight_Popup_View_Intro.php';
		exit();
	}



	public function w3tc_ajax_cdnfsd_limelight_save() {
		$short_name = Util_Request::get_string( 'short_name' );
		$username = Util_Request::get_string( 'username' );
		$api_key = Util_Request::get_string( 'api_key' );

		try {
			$api = new Cdnfsd_LimeLight_Api( $short_name, $username, $api_key );
			$url = Util_Environment::home_domain_root_url() . '/';

			$items = array(
				array(
					'pattern' => $url,
					'exact' => true,
					'evict' => false,
					'incqs' => false
				)
			);

			$api->purge( $items );
		} catch ( \Exception $ex ) {
			$this->render_intro( array(
					'error_message' => 'Failed to make test purge request: ' . $ex->getMessage()
				) );
			exit();
		}

		$c = Dispatcher::config();
		$c->set( 'cdnfsd.limelight.short_name', $short_name );
		$c->set( 'cdnfsd.limelight.username', $username );
		$c->set( 'cdnfsd.limelight.api_key', $api_key );
		$c->save();

		include  W3TC_DIR . '/Cdnfsd_LimeLight_Popup_View_Success.php';
		exit();
	}
}
