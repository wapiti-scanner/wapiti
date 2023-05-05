<?php
/**
 * Plugin Name: Display Recent WordPress Posts Widget
 * Description: Displays recent posts from a WordPress.com or Jetpack-enabled self-hosted WordPress site.
 * Version: 1.0
 * Author: Brad Angelcyk, Kathryn Presner, Justin Shreve, Carolyn Sonnek
 * Author URI: https://automattic.com
 * License: GPL2
 * Text Domain: jetpack
 *
 * @package automattic/jetpack
 */

/**
 * Disable direct access/execution to/of the widget code.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require __DIR__ . '/wordpress-post-widget/class.jetpack-display-posts-widget-base.php';
require __DIR__ . '/wordpress-post-widget/class.jetpack-display-posts-widget.php';

add_action( 'widgets_init', 'jetpack_display_posts_widget' );
/**
 * Registers widget Jetpack_Display_Posts_Widget
 */
function jetpack_display_posts_widget() {
	register_widget( 'Jetpack_Display_Posts_Widget' );
}

/**
 * Cron tasks
 */

add_filter( 'cron_schedules', 'jetpack_display_posts_widget_cron_intervals' ); // phpcs:ignore WordPress.WP.CronInterval.CronSchedulesInterval

/**
 * Adds 10 minute running interval to the cron schedules.
 *
 * @param array $current_schedules Currently defined schedules list.
 *
 * @return array
 */
function jetpack_display_posts_widget_cron_intervals( $current_schedules ) {

	/**
	 * Only add the 10 minute interval if it wasn't already set.
	 */
	if ( ! isset( $current_schedules['minutes_10'] ) ) {
		$current_schedules['minutes_10'] = array(
			'interval' => 10 * MINUTE_IN_SECONDS,
			'display'  => 'Every 10 minutes',
		);
	}

	return $current_schedules;
}

/**
 * Execute the cron task
 */
add_action( 'jetpack_display_posts_widget_cron_update', 'jetpack_display_posts_update_cron_action' );
/**
 * Run the Jetpack_Display_Posts_Widget cron task.
 */
function jetpack_display_posts_update_cron_action() {
	$widget = new Jetpack_Display_Posts_Widget();
	$widget->cron_task();
}

/**
 * Handle activation procedures for the cron.
 *
 * `updating_jetpack_version` - Handle cron activation when Jetpack gets updated. It's here
 *                              to cover the first cron activation after the update.
 *
 * `jetpack_activate_module_widgets` - Activate the cron when the Extra Sidebar widgets are activated.
 *
 * `activated_plugin` - Activate the cron when Jetpack gets activated.
 */
add_action( 'updating_jetpack_version', 'jetpack_display_posts_widget_conditionally_activate_cron' );
add_action( 'jetpack_activate_module_widgets', 'Jetpack_Display_Posts_Widget::activate_cron' );
add_action( 'activated_plugin', 'jetpack_conditionally_activate_cron_on_plugin_activation' );

/**
 * Executed when Jetpack gets activated. Tries to activate the cron if it is needed.
 *
 * @param string $plugin_file_name The plugin file that was activated.
 */
function jetpack_conditionally_activate_cron_on_plugin_activation( $plugin_file_name ) {
	if ( plugin_basename( JETPACK__PLUGIN_FILE ) === $plugin_file_name ) {
		jetpack_display_posts_widget_conditionally_activate_cron();
	}
}

/**
 * Activates the cron only when needed.
 *
 * @see Jetpack_Display_Posts_Widget::should_cron_be_running
 */
function jetpack_display_posts_widget_conditionally_activate_cron() {
	$widget = new Jetpack_Display_Posts_Widget();
	if ( $widget->should_cron_be_running() ) {
		$widget->activate_cron();
	}

	unset( $widget );
}

/**
 * End of cron activation handling.
 */

/**
 * Handle deactivation procedures where they are needed.
 *
 * If Extra Sidebar Widgets module is deactivated, the cron is not needed.
 *
 * If Jetpack is deactivated, the cron is not needed.
 */
add_action( 'jetpack_deactivate_module_widgets', 'Jetpack_Display_Posts_Widget::deactivate_cron_static' );
register_deactivation_hook( plugin_basename( JETPACK__PLUGIN_FILE ), 'Jetpack_Display_Posts_Widget::deactivate_cron_static' );
