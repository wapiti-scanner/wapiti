<?php
/**
 * Module Name: Post List
 * Module Description: Display extra information alongside each post in your dashboard’s Posts screen.
 * Sort Order: 31
 * Recommendation Order: 12
 * First Introduced: 11.3
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Admin
 * Feature: Appearance
 * Additional Search Queries: post, admin, list
 *
 * @package automattic/jetpack
 */

/**
 * Initialize the post-list module.
 */
add_action( 'admin_init', array( '\Automattic\\Jetpack\\Post_List\\Post_List', 'configure' ) );
