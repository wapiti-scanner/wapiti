<?php
namespace W3TC;

class UserExperience_OEmbed_Extension {
	public function run() {
		add_action( 'wp_footer', array( $this, 'wp_footer' ) );
	}



	public function wp_footer() {
		wp_deregister_script( 'wp-embed' );
	}
}



$o = new UserExperience_OEmbed_Extension();
$o->run();
