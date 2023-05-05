<?php
/**
 * Milestone Widget Loader.
 *
 * @package automattic/jetpack
 */

/**
 * The widget class.
 */
require_once __DIR__ . '/class-milestone-widget.php';

/**
 * Registers the widget for use!
 */
function jetpack_register_widget_milestone() {
	register_widget( 'Milestone_Widget' );
}
add_action( 'widgets_init', 'jetpack_register_widget_milestone' );
