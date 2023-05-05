<?php
namespace W3TC;

class Extension_CloudFlare_Page {
	static public function admin_print_scripts_w3tc_extensions() {
		if ( ( isset( $_REQUEST['extension'] ) &&
		Util_Request::get_string( 'extension' ) == 'cloudflare' ) ||
			( isset( $_REQUEST['page'] ) &&
			Util_Request::get_string( 'page' ) == 'w3tc_cdnfsd' ) ) {
			wp_enqueue_script( 'w3tc_extension_cloudflare',
				plugins_url( 'Extension_CloudFlare_Page_View.js', W3TC_FILE ),
				array( 'jquery' ), '1.0' );
		}
	}



	static public function w3tc_settings_box_cdnfsd() {
		include  W3TC_DIR . '/Extension_CloudFlare_Cdn_Page_View.php';
	}



	static public function w3tc_extension_page_cloudflare() {
		$c = Dispatcher::config();
		$api = Extension_CloudFlare_SettingsForUi::api();

		$email = $c->get_string( array( 'cloudflare', 'email' ) );
		$key = $c->get_string( array( 'cloudflare', 'key' ) );
		$zone_id = $c->get_string( array( 'cloudflare', 'zone_id' ) );

		if ( empty( $email ) || empty( $key ) || empty( $zone_id ) ) {
			$state = 'not_configured';
		} else {
			$settings = array();

			try {
				$settings =
					Extension_CloudFlare_SettingsForUi::settings_get( $api );
				$state = 'available';
			} catch ( \Exception $ex ) {
				$state = 'not_available';
				$error_message = $ex->getMessage();

			}
		}

		$config = $c;
		include  W3TC_DIR . '/Extension_CloudFlare_Page_View.php';
	}



	static private function cloudflare_checkbox( $settings, $data ) {
		if ( !isset( $settings[$data['key']] ) )
			return;

		$value = ( $settings[$data['key']]['value'] == 'on' );
		$disabled = !$settings[$data['key']]['editable'];

		Util_Ui::table_tr( array(
				'id' => $data['key'],
				'label' => $data['label'],
				'checkbox' => array(
					'name' => 'cloudflare_api_' . $data['key'],
					'value' => $value,
					'disabled' => $disabled,
					'label' => 'Enable'
				),
				'description' => $data['description']
			) );
	}



	static private function cloudflare_selectbox( $settings, $data ) {
		if ( !isset( $settings[$data['key']] ) )
			return;

		$value = $settings[$data['key']]['value'];
		$disabled = !$settings[$data['key']]['editable'];

		Util_Ui::table_tr( array(
				'id' => $data['key'],
				'label' => $data['label'],
				'selectbox' => array(
					'name' => 'cloudflare_api_' . $data['key'],
					'value' => $value,
					'disabled' => $disabled,
					'values' => $data['values']
				),
				'description' => $data['description']
			) );
	}



	static private function cloudflare_textbox( $settings, $data ) {
		if ( !isset( $settings[$data['key']] ) )
			return;

		$value = $settings[$data['key']]['value'];
		$disabled = !$settings[$data['key']]['editable'];

		Util_Ui::table_tr( array(
				'id' => $data['key'],
				'label' => $data['label'],
				'textbox' => array(
					'name' => 'cloudflare_api_' . $data['key'],
					'value' => $value,
					'disabled' => $disabled
				),
				'description' => $data['description']
			) );
	}



	static private function cloudflare_button_save( $id = '' ) {
		$b1_id = 'w3tc_cloudflare_save_' . $id;

		echo '<p class="submit">';
		echo wp_kses(
			Util_Ui::nonce_field( 'w3tc' ),
			array(
				'input' => array(
					'type'  => array(),
					'name'  => array(),
					'value' => array(),
				),
			)
		);
		echo '<input type="submit" id="' . esc_attr( $b1_id ) .
			'" name="w3tc_cloudflare_save_settings" ' .
			' class="w3tc-button-save button-primary" ' .
			' value="' . esc_attr( __( 'Save CloudFlare settings', 'w3-total-cache' ) ) .
			'" />';
		echo '</p>';
	}
}
