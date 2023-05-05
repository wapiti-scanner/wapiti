<?php
namespace W3TC;

class Support_Page {
	/**
	 * called from Generic_Plugin_Admin on action
	 */
	static public function admin_print_scripts_w3tc_support() {
		$url = get_home_url();
		if ( substr( $url, 0, 7 ) == 'http://' )
			$url = substr( $url, 7 );
		elseif ( substr( $url, 0, 8 ) == 'https://' )
			$url = substr( $url, 8 );

		// values from widget
		$w3tc_support_form_hash = 'm5pom8z0qy59rm';
		$w3tc_support_field_name = '';
		$w3tc_support_field_value = '';

		$service_item_val = Util_Request::get_integer( 'service_item' );
		if ( ! empty( $service_item_val ) ) {
			$pos = $service_item_val;

			$v = get_site_option( 'w3tc_generic_widgetservices' );
			try {
				$v = json_decode( $v, true );
				if ( isset( $v['items'] ) && isset( $v['items'][$pos] )) {
					$i = $v['items'][$pos];
					$w3tc_support_form_hash = $i['form_hash'];
					$w3tc_support_field_name = $i['parameter_name'];
					$w3tc_support_field_value = $i['parameter_value'];
				}
			} catch ( \Exception $e ) {
			}
		}

		$u = wp_get_current_user();

		// w3tc-options script is already queued so attach to it
		// just to make vars printed (while it's not related by semantics)
		wp_localize_script( 'w3tc-options', 'w3tc_support_data',
			array(
				'home_url' => $url,
				'email' => get_bloginfo( 'admin_email' ),
				'first_name' => $u->first_name,
				'last_name' => $u->last_name,
				'form_hash' => $w3tc_support_form_hash,
				'field_name' => $w3tc_support_field_name,
				'field_value' => $w3tc_support_field_value,
				'postprocess' => urlencode( urlencode(
					Util_Ui::admin_url(
						wp_nonce_url( 'admin.php', 'w3tc' ) . '&page=w3tc_support&done'
					) ) )
			)
		);
	}
	/**
	 * Support tab
	 *
	 * @return void
	 */
	function options() {
		if ( ! empty( Util_Request::get_string( 'done' ) ) ) {
			$postprocess_url =
				'admin.php?page=w3tc_support&w3tc_support_send_details' .
				'&_wpnonce=' . rawurlencode( Util_Request::get_string( '_wpnonce' ) );
			foreach ( $_GET as $p => $v ) {
				if ( 'page' !== $p && '_wpnonce' !== $p && 'done' !== $p ) {
					$postprocess_url .= '&' . rawurlencode( $p ) . '=' . rawurlencode( Util_Request::get_string( $p ) );
				}
			}

			// terms accepted as a part of form
			Licensing_Core::terms_accept();

			include  W3TC_DIR . '/Support_Page_View_DoneContent.php';
		} else
			include  W3TC_DIR . '/Support_Page_View_PageContent.php';
	}
}
