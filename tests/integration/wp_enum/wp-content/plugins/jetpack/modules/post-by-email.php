<?php
/**
 * Module Name: Post by email
 * Module Description: Publish posts by sending an email
 * First Introduced: 2.0
 * Sort Order: 14
 * Requires Connection: Yes
 * Requires User Connection: Yes
 * Auto Activate: No
 * Module Tags: Writing
 * Feature: Writing
 * Additional Search Queries: post by email, email
 *
 * @package automattic/jetpack
 */

/**
 * Require the PBE Class.
 */
require_once __DIR__ . '/post-by-email/class-jetpack-post-by-email.php';

add_action( 'jetpack_modules_loaded', array( 'Jetpack_Post_By_Email', 'init' ) );

Jetpack::enable_module_configurable( __FILE__ );
