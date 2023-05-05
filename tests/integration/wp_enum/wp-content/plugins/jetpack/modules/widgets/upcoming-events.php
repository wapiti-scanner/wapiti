<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Upcoming Events widget
 *
 * It relies on the icalendar-reader library.
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Register the widget.
 */
function upcoming_events_register_widgets() {
	register_widget( Jetpack_Upcoming_Events_Widget::class );
}
add_action( 'widgets_init', 'upcoming_events_register_widgets' );

/**
 * Widget class.
 */
class Jetpack_Upcoming_Events_Widget extends WP_Widget {
	/**
	 * Constructor
	 */
	public function __construct() {
		parent::__construct(
			'upcoming_events_widget',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', __( 'Upcoming Events', 'jetpack' ) ),
			array(
				'description'                 => __( 'Display upcoming events from an iCalendar feed.', 'jetpack' ),
				'customize_selective_refresh' => true,
			)
		);
		if ( is_active_widget( false, false, $this->id_base ) ) {
			add_action( 'wp_head', array( $this, 'css' ) );
		}
	}

	/**
	 * Output CSS in the header everywhere where the widget is active.
	 */
	public function css() {
		?>
<style type="text/css">
.upcoming-events li {
	margin-bottom: 10px;
}
.upcoming-events li span {
	display: block;
}
</style>
		<?php
	}

	/**
	 * Displays the form for this widget on the Widgets page of the WP Admin area.
	 *
	 * @param array $instance Instance configuration.
	 *
	 * @return void
	 */
	public function form( $instance ) {
		$defaults = array(
			'title'    => __( 'Upcoming Events', 'jetpack' ),
			'feed-url' => '',
			'count'    => 3,
		);
		$instance = array_merge( $defaults, (array) $instance );
		?>

		<p>
		<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"><?php esc_html_e( 'Title:', 'jetpack' ); ?></label>
		<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['title'] ); ?>" />
		</p>

		<p>
		<label for="<?php echo esc_attr( $this->get_field_id( 'feed-url' ) ); ?>"><?php esc_html_e( 'iCalendar Feed URL:', 'jetpack' ); ?></label>
		<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'feed-url' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'feed-url' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['feed-url'] ); ?>" />
		</p>

		<p>
		<label for="<?php echo esc_attr( $this->get_field_id( 'count' ) ); ?>"><?php esc_html_e( 'Items to show:', 'jetpack' ); ?></label>
		<select id="<?php echo esc_attr( $this->get_field_id( 'count' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'count' ) ); ?>">
			<?php for ( $i = 1; $i <= 10; $i++ ) { ?>
				<option <?php selected( $instance['count'], $i ); ?>><?php echo (int) $i; ?></option>
			<?php } ?>
			<option value="0" <?php selected( $instance['count'], 0 ); ?>><?php esc_html_e( 'All', 'jetpack' ); ?></option>
		</select>
		</p>
		<?php
	}

	/**
	 * Deals with the settings when they are saved by the admin.
	 *
	 * @param array $new_instance New configuration values.
	 * @param array $old_instance Old configuration values.
	 *
	 * @return array
	 */
	public function update( $new_instance, $old_instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$instance             = array();
		$instance['title']    = wp_strip_all_tags( $new_instance['title'] );
		$instance['feed-url'] = wp_strip_all_tags( $new_instance['feed-url'] );
		$instance['count']    = min( absint( $new_instance['count'] ), 10 ); // 10 or less
		return $instance;
	}

	/**
	 * Outputs the HTML for this widget.
	 *
	 * @param array $args     An array of standard parameters for widgets in this theme.
	 * @param array $instance An array of settings for this widget instance.
	 *
	 * @return void Echoes it's output
	 */
	public function widget( $args, $instance ) {
		require_once JETPACK__PLUGIN_DIR . '/_inc/lib/icalendar-reader.php';

		$ical           = new iCalendarReader();
		$events         = $ical->get_events( $instance['feed-url'], $instance['count'] );
		$events         = $this->apply_timezone_offset( $events );
		$ical->timezone = null;

		echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		if ( ! empty( $instance['title'] ) ) {
			echo $args['before_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo esc_html( $instance['title'] );
			echo $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		if ( ! $events ) : // nothing to display?
			?>
			<p><?php esc_html_e( 'No upcoming events', 'jetpack' ); ?></p>
			<?php
		else :
			?>
			<ul class="upcoming-events">
				<?php foreach ( $events as $event ) : ?>
				<li>
					<strong class="event-summary">
						<?php
						echo $ical->escape( stripslashes( $event['SUMMARY'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- this method is built to escape.
						?>
					</strong>
					<span class="event-when"><?php echo esc_html( $ical->formatted_date( $event ) ); ?></span>
					<?php if ( ! empty( $event['LOCATION'] ) ) : ?>
						<span class="event-location">
							<?php
							echo $ical->escape( stripslashes( $event['LOCATION'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- this method is built to escape.
							?>
						</span>
					<?php endif; ?>
					<?php if ( ! empty( $event['DESCRIPTION'] ) ) : ?>
						<span class="event-description">
							<?php
							echo wp_trim_words( $ical->escape( stripcslashes( $event['DESCRIPTION'] ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- this method is built to escape.
							?>
						</span>
					<?php endif; ?>
				</li>
				<?php endforeach; ?>
			</ul>
			<?php
		endif;

		echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This action is documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'upcoming_events' );
	}

	/**
	 * Left this function here for backward compatibility
	 * just incase a site using jetpack is also using this function
	 *
	 * @param array|false $events Array of events, false on failure.
	 */
	private function apply_timezone_offset( $events ) {
		require_once JETPACK__PLUGIN_DIR . '/_inc/lib/icalendar-reader.php';

		return ( new iCalendarReader() )->apply_timezone_offset( $events );
	}
}
