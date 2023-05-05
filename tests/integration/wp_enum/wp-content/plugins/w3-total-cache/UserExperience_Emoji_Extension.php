<?php
namespace W3TC;

class UserExperience_Emoji_Extension {
	public function run() {
		remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
		remove_action( 'wp_print_styles', 'print_emoji_styles' );
		remove_filter( 'wp_mail', 'wp_staticize_emoji_for_email' );

		remove_filter( 'the_content_feed', 'wp_staticize_emoji' );
		remove_filter( 'comment_text_rss', 'wp_staticize_emoji' );

		remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
		remove_action( 'admin_print_styles', 'print_emoji_styles' );

		add_filter( 'tiny_mce_plugins', array( $this, 'tiny_mce_plugins' ) );
		add_filter( 'wp_resource_hints',
			array( $this, 'wp_resource_hints' ), 10, 2 );
	}



	public function tiny_mce_plugins( $plugins ) {
		if ( !is_array( $plugins ) ) {
			return array();
		}

		return array_filter( $plugins,
			function( $v ) {
				return $v != 'wpemoji';
			}
		);
	}



	public function wp_resource_hints( $urls, $relation_type ) {
		if ( !is_array( $urls ) || $relation_type != 'dns-prefetch' ) {
			return $urls;
		}

		// remove s.w.org dns-prefetch used by emojis
		return array_filter( $urls,
			function( $v ) {
				return ( substr( $v, 0, 16) != 'https://s.w.org/' );
			}
		);
	}
}



$o = new UserExperience_Emoji_Extension();
$o->run();
