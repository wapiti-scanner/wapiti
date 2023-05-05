<?php

if ( ! defined( 'ABSPATH' ) ) {
	die();
}

function w3tc_old_php_message() {
	$m = __( 'Please update your PHP. <strong>W3 Total Cache</strong> requires PHP version 5.6 or above', 'w3-total-cache' );
	return $m;
}

function w3tc_old_php_activate() {
	echo esc_html( w3tc_old_php_message() );
	exit();
}

function w3tc_old_php_admin_notices() {
	?>
	<div class="notice error notice-error">
		<p><?php echo esc_html( w3tc_old_php_message() ); ?></p>
	</div>
	<?php
}

add_action( 'admin_notices', 'w3tc_old_php_admin_notices' );
