<?php
/**
 * Module Name: Markdown
 * Module Description: Write posts or pages in plain-text Markdown syntax
 * Sort Order: 31
 * First Introduced: 2.8
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Writing
 * Feature: Writing
 * Additional Search Queries: md, markdown
 *
 * @package automattic/jetpack
 */

// Require the markdown class file.
require __DIR__ . '/markdown/easy-markdown.php';

/**
 * Remove checkbox set in modules/markdown/easy-markdown.php.
 * We don't just remove the register_setting call there because the checkbox is
 * needed on WordPress.com, where the file is sync'ed verbatim.
 */
function jetpack_markdown_posting_always_on() {
	// why oh why isn't there a remove_settings_field?
	global $wp_settings_fields;
	if ( isset( $wp_settings_fields['writing']['default'][ WPCom_Markdown::POST_OPTION ] ) ) {
		unset( $wp_settings_fields['writing']['default'][ WPCom_Markdown::POST_OPTION ] );
	}
}
add_action( 'admin_init', 'jetpack_markdown_posting_always_on', 11 );
