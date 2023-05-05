<?php
namespace W3TC;



class Extension_Swarmify_Page {
	public function render_content() {
		$config = Dispatcher::config();

		$api_key = $config->get_string( array( 'swarmify', 'api_key' ) );
		$authorized = !empty( $api_key );

		$email = get_bloginfo( 'admin_email' );
		$u = wp_get_current_user();
		$name = $u->first_name .
			( empty( $u->first_name ) ? '' : ' ' ) .
			$u->last_name;

		$swarmify_signup_url = Extension_Swarmify_Core::signup_url();

		include  W3TC_DIR . '/Extension_Swarmify_Page_View.php';
	}
}
