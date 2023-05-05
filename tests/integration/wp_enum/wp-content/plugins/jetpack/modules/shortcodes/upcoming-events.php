<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Display a list of upcoming events from a calendar.
 *
 * @package automattic/jetpack
 */

/**
 * Register a upcomingevents shortcode.
 * Most of the heavy lifting done in iCalendarReader class,
 * where the icalendar_render_events() function controls the display.
 */
class Upcoming_Events_Shortcode {

	/**
	 * Register things.
	 */
	public static function init() {
		add_shortcode( 'upcomingevents', array( __CLASS__, 'shortcode' ) );
	}

	/**
	 * Register the shortcode.
	 *
	 * @param array $atts Shortcode attributes.
	 */
	public static function shortcode( $atts = array() ) {
		require_once JETPACK__PLUGIN_DIR . '/_inc/lib/icalendar-reader.php';
		$atts = shortcode_atts(
			array(
				'url'    => '',
				'number' => 0,
			),
			$atts,
			'upcomingevents'
		);
		$args = array(
			'context' => 'shortcode',
			'number'  => absint( $atts['number'] ),
		);

		if ( empty( $atts['url'] ) ) {
			// If the current user can access the Appearance->Widgets page.
			if ( current_user_can( 'edit_theme_options' ) ) {
				return sprintf( '<p>%s</p>', __( 'You must specify a URL to an iCalendar feed in the shortcode. This notice is only displayed to administrators.', 'jetpack' ) );
			}
			return self::no_upcoming_event_text();
		}
		$events = icalendar_render_events( $atts['url'], $args );

		if ( ! $events ) {
			$events = self::no_upcoming_event_text();
		}

		return $events;
	}

	/**
	 * Returns No Upcoming Event text.
	 */
	private static function no_upcoming_event_text() {
		return sprintf( '<p>%s</p>', __( 'No upcoming events', 'jetpack' ) );
	}
}
add_action( 'plugins_loaded', array( 'Upcoming_Events_Shortcode', 'init' ), 101 );
