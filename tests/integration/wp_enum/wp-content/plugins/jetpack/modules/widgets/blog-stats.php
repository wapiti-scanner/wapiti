<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileNam
/**
 * Blog Stats Widget.
 *
 * @since 4.5.0
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Stats\WPCOM_Stats;

/**
 * Disable direct access/execution to/of the widget code.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Blog Stats Widget.
 *
 * Displays all time stats for that site.
 *
 * @since 4.5.0
 */
class Jetpack_Blog_Stats_Widget extends WP_Widget {

	/**
	 * Constructor
	 */
	public function __construct() {
		$widget_ops = array(
			'classname'                   => 'blog-stats',
			'description'                 => esc_html__( 'Show a hit counter for your blog.', 'jetpack' ),
			'customize_selective_refresh' => true,
		);
		parent::__construct(
			'blog-stats',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', esc_html__( 'Blog Stats', 'jetpack' ) ),
			$widget_ops
		);
		$this->alt_option_name = 'widget_statscounter';
	}

	/**
	 * Return an associative array of default values
	 *
	 * These values are used in new widgets.
	 *
	 * @return array Array of default values for the Widget's options
	 */
	public function defaults() {
		return array(
			'title' => esc_html__( 'Blog Stats', 'jetpack' ),
			/* Translators: Number of views, plural */
			'hits'  => esc_html__( 'hits', 'jetpack' ),
		);
	}

	/**
	 * Return All Time Stats for that blog.
	 *
	 * We query the WordPress.com Stats REST API endpoint.
	 *
	 * @uses Automattic\Jetpack\Stats\WPCOM_Stats->get_stats. That function caches data locally for 5 minutes.
	 *
	 * @return string|false $views All Time Stats for that blog.
	 */
	public function get_stats() {
		// Get data from the WordPress.com Stats REST API endpoint.
		$stats = convert_stats_array_to_object( ( new WPCOM_Stats() )->get_stats( array( 'fields' => 'stats' ) ) );

		if ( isset( $stats->stats->views ) ) {
			return $stats->stats->views;
		} else {
			return false;
		}
	}

	/**
	 * Back end widget form.
	 *
	 * @see WP_Widget::form()
	 *
	 * @param array $instance Previously saved values from database.
	 *
	 * @return void
	 */
	public function form( $instance ) {
		$instance = wp_parse_args( $instance, $this->defaults() );
		?>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"><?php esc_html_e( 'Title:', 'jetpack' ); ?></label>
			<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['title'] ); ?>" />
		</p>
		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'hits' ) ); ?>"><?php esc_html_e( 'Pageview Description:', 'jetpack' ); ?></label>
			<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'hits' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'hits' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['hits'] ); ?>" />
		</p>
		<p><?php esc_html_e( 'Hit counter is delayed by up to 60 seconds.', 'jetpack' ); ?></p>

		<?php
	}

	/**
	 * Sanitize widget form values as they are saved.
	 *
	 * @see WP_Widget::update()
	 *
	 * @param array $new_instance Values just sent to be saved.
	 * @param array $old_instance Previously saved values from database.
	 *
	 * @return array Updated safe values to be saved.
	 */
	public function update( $new_instance, $old_instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$instance          = array();
		$instance['title'] = wp_kses( $new_instance['title'], array() );
		$instance['hits']  = wp_kses( $new_instance['hits'], array() );

		return $instance;
	}

	/**
	 * Front-end display of widget.
	 *
	 * @see WP_Widget::widget()
	 *
	 * @param array $args     Widget arguments.
	 * @param array $instance Saved values from database.
	 */
	public function widget( $args, $instance ) {
		$instance = wp_parse_args( $instance, $this->defaults() );

		/** This filter is documented in wp-includes/widgets/class-wp-widget-pages.php */
		$title = apply_filters( 'widget_title', $instance['title'] );

		echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		if ( ! empty( $title ) ) {
			echo $args['before_title'] . $title . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		// Get the Site Stats.
		$views = $this->get_stats();

		if ( 0 === $views ) {
			esc_html_e( 'There is nothing to display yet', 'jetpack' );
		} elseif ( $views ) {
			printf(
				'<ul><li>%1$s %2$s</li></ul>',
				number_format_i18n( $views ),
				isset( $instance['hits'] ) ? esc_html( $instance['hits'] ) : ''
			);
		} else {
			esc_html_e( 'There was an issue retrieving stats. Please try again later.', 'jetpack' );
		}

		echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This action is already documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'blog_stats' );
	}
}

/**
 * If the Stats module is active in a recent version of Jetpack, register the widget.
 *
 * @since 4.5.0
 */
function jetpack_blog_stats_widget_init() {
	if ( Jetpack::is_module_active( 'stats' ) ) {
		register_widget( 'Jetpack_Blog_Stats_Widget' );
	}
}
add_action( 'widgets_init', 'jetpack_blog_stats_widget_init' );
