<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

if ( empty( $cnames ) ) {
} elseif ( count( $cnames ) == 1 ) {
	echo '<div class="w3tc_cdn_cnames_readonly">' . esc_html( $cnames[0] ) . '</div>';
} else {
	echo '<ol class="w3tc_cdn_cnames_readonly">';

	foreach ( $cnames as $index => $cname ) {
		$label = '';

		if ( 0 === $index ) {
			$label = __( '(reserved for CSS)', 'w3-total-cache' );
		} elseif ( 1 === $index ) {
			$label = __( '(reserved for JS in <head>)', 'w3-total-cache' );
		} elseif ( 2 === $index ) {
			$label = __( '(reserved for JS after <body>)', 'w3-total-cache' );
		} elseif ( 3 === $index ) {
			$label = __( '(reserved for JS before </body>)', 'w3-total-cache' );
		} else {
			$label = '';
		}

		echo '<li>' . esc_html( $cname ) . '<span class="w3tc_cdn_cname_comment">';
		echo esc_html( $label );
		echo '</span></li>';
	}

	echo '</ol>';
}
