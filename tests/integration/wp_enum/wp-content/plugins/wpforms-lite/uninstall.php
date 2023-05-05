<?php
/**
 * Uninstall WPForms.
 *
 * Remove:
 * - Entries table
 * - Entry Meta table
 * - Entry fields table
 * - Form Preview page
 * - wpforms_log post type posts and post_meta
 * - wpforms post type posts and post_meta
 * - WPForms settings/options
 * - WPForms user meta
 * - WPForms term meta
 * - WPForms Uploads
 *
 * @since 1.4.5
 *
 * @var WP_Filesystem_Base $wp_filesystem
 */

// phpcs:disable WordPress.DB.DirectDatabaseQuery

// Exit if accessed directly.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Load plugin file.
require_once 'wpforms.php';

// Disable Action Schedule Queue Runner.
if ( class_exists( 'ActionScheduler_QueueRunner' ) ) {
	ActionScheduler_QueueRunner::instance()->unhook_dispatch_async_request();
}

// Confirm user has decided to remove all data, otherwise stop.
$settings = get_option( 'wpforms_settings', [] );

if ( empty( $settings['uninstall-data'] ) || is_plugin_active( 'wpforms/wpforms.php' ) || is_plugin_active( 'wpforms-lite/wpforms.php' ) ) {
	return;
}

global $wpdb;

// Delete entries table.
$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wpforms_entries' );

// Delete entry meta table.
$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wpforms_entry_meta' );

// Delete entry fields table.
$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wpforms_entry_fields' );

// Delete tasks meta table.
// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query( 'DROP TABLE IF EXISTS ' . \WPForms\Tasks\Meta::get_table_name() );

// Delete logger table.
// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query( 'DROP TABLE IF EXISTS ' . \WPForms\Logger\Repository::get_table_name() );

/**
 * Delete tables that might be created by "Add-ons".
 *
 * 1. Form Locker.
 * 2. User Journey.
 */
$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wpforms_form_locker_email_verification' );
$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wpforms_user_journey' );

// Delete Preview page.
$preview_page = get_option( 'wpforms_preview_page', false );

if ( ! empty( $preview_page ) ) {
	wp_delete_post( $preview_page, true );
}

// Delete wpforms and wpforms_log post type posts/post_meta.
$wpforms_posts = get_posts(
	[
		'post_type'   => [ 'wpforms_log', 'wpforms' ],
		'post_status' => 'any',
		'numberposts' => - 1,
		'fields'      => 'ids',
	]
);

if ( $wpforms_posts ) {
	foreach ( $wpforms_posts as $wpforms_post ) {
		wp_delete_post( $wpforms_post, true );
	}
}

// Delete all the plugin settings.
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'wpforms\_%'" );

// Delete widget settings.
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'widget\_wpforms%'" );

// Delete options from the previous version of the Notifications functionality.
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_amn\_wpforms\_%'" );

// Delete plugin user meta.
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'wpforms\_%'" );

// Delete plugin term meta.
$wpdb->query( "DELETE FROM {$wpdb->termmeta} WHERE meta_key LIKE 'wpforms\_%'" );

// Remove any transients we've left behind.
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_wpforms\_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_site\_transient\_wpforms\_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_timeout\_wpforms\_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_site\_transient\_timeout\_wpforms\_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_wpforms\_transient\_%'" );

global $wp_filesystem;

// Remove uploaded files.
$uploads_directory = wp_upload_dir();

if ( empty( $uploads_directory['error'] ) ) {
	$wp_filesystem->rmdir( $uploads_directory['basedir'] . '/wpforms/', true );
}

// Remove translation files.
$languages_directory = defined( 'WP_LANG_DIR' ) ? trailingslashit( WP_LANG_DIR ) : trailingslashit( WP_CONTENT_DIR ) . 'languages/';
$translations        = glob( wp_normalize_path( $languages_directory . 'plugins/wpforms-*' ) );

if ( ! empty( $translations ) ) {
	foreach ( $translations as $file ) {
		$wp_filesystem->delete( $file );
	}
}

// Remove plugin cron jobs.
wp_clear_scheduled_hook( 'wpforms_email_summaries_cron' );

// Unschedule all plugin ActionScheduler actions.
// Don't use wpforms() because 'tasks' in core are registered on `init` hook,
// which is not executed on uninstall.
( new \WPForms\Tasks\Tasks() )->cancel_all();
