<?php
/*
Plugin Name: Contact Form 7
Plugin URI: https://contactform7.com/
Description: Just another contact form plugin. Simple but flexible.
Author: Takayuki Miyoshi
Author URI: https://ideasilo.wordpress.com/
Text Domain: contact-form-7
Domain Path: /languages/
Version: 5.7.6
*/

define( 'WPCF7_VERSION', '5.7.6' );

define( 'WPCF7_REQUIRED_WP_VERSION', '6.0' );

define( 'WPCF7_TEXT_DOMAIN', 'contact-form-7' );

define( 'WPCF7_PLUGIN', __FILE__ );

define( 'WPCF7_PLUGIN_BASENAME', plugin_basename( WPCF7_PLUGIN ) );

define( 'WPCF7_PLUGIN_NAME', trim( dirname( WPCF7_PLUGIN_BASENAME ), '/' ) );

define( 'WPCF7_PLUGIN_DIR', untrailingslashit( dirname( WPCF7_PLUGIN ) ) );

define( 'WPCF7_PLUGIN_MODULES_DIR', WPCF7_PLUGIN_DIR . '/modules' );

if ( ! defined( 'WPCF7_LOAD_JS' ) ) {
	define( 'WPCF7_LOAD_JS', true );
}

if ( ! defined( 'WPCF7_LOAD_CSS' ) ) {
	define( 'WPCF7_LOAD_CSS', true );
}

if ( ! defined( 'WPCF7_AUTOP' ) ) {
	define( 'WPCF7_AUTOP', true );
}

if ( ! defined( 'WPCF7_USE_PIPE' ) ) {
	define( 'WPCF7_USE_PIPE', true );
}

if ( ! defined( 'WPCF7_ADMIN_READ_CAPABILITY' ) ) {
	define( 'WPCF7_ADMIN_READ_CAPABILITY', 'edit_posts' );
}

if ( ! defined( 'WPCF7_ADMIN_READ_WRITE_CAPABILITY' ) ) {
	define( 'WPCF7_ADMIN_READ_WRITE_CAPABILITY', 'publish_pages' );
}

if ( ! defined( 'WPCF7_VERIFY_NONCE' ) ) {
	define( 'WPCF7_VERIFY_NONCE', false );
}

if ( ! defined( 'WPCF7_USE_REALLY_SIMPLE_CAPTCHA' ) ) {
	define( 'WPCF7_USE_REALLY_SIMPLE_CAPTCHA', false );
}

if ( ! defined( 'WPCF7_VALIDATE_CONFIGURATION' ) ) {
	define( 'WPCF7_VALIDATE_CONFIGURATION', true );
}

// Deprecated, not used in the plugin core. Use wpcf7_plugin_url() instead.
define( 'WPCF7_PLUGIN_URL',
	untrailingslashit( plugins_url( '', WPCF7_PLUGIN ) )
);

require_once WPCF7_PLUGIN_DIR . '/load.php';
