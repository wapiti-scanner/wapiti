<?php
namespace W3TC;



class Extension_Swarmify_Core {
	static public function signup_url() {
		$email = get_bloginfo( 'admin_email' );
		$u = wp_get_current_user();
		$name = $u->first_name .
			( empty( $u->first_name ) ? '' : ' ' ) .
			$u->last_name;

		return 'https://www.swarmify.com/landing/w3tc?' .
			'email=' . urlencode( $email ) .
			'&name=' . urlencode( $name ) .
			'&return=' .
			urlencode( wp_nonce_url( Util_Ui::admin_url( 'admin.php' ),	'w3tc' ) .
				'&page=w3tc_extensions&w3tc_swarmify_set_key=set' );
	}
}
