<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * RSS Links Widget
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Register the widget.
 */
function jetpack_rss_links_widget_init() {
	register_widget( Jetpack_RSS_Links_Widget::class );
}
add_action( 'widgets_init', 'jetpack_rss_links_widget_init' );

/**
 * RSS Links Widget class.
 */
class Jetpack_RSS_Links_Widget extends WP_Widget {
	/**
	 * Constructor
	 */
	public function __construct() {
		$widget_ops = array(
			'classname'                   => 'widget_rss_links',
			'description'                 => __( "Links to your blog's RSS feeds", 'jetpack' ),
			'customize_selective_refresh' => true,
		);
		parent::__construct(
			'rss_links',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', __( 'RSS Links', 'jetpack' ) ),
			$widget_ops
		);
	}

	/**
	 * Display the widget.
	 *
	 * @param array $args Display arguments including before_title, after_title, before_widget, and after_widget.
	 * @param array $instance The settings for the particular instance of the widget.
	 */
	public function widget( $args, $instance ) {
		$instance = wp_parse_args( (array) $instance, $this->defaults() );

		$before_widget = isset( $args['before_widget'] ) ? $args['before_widget'] : '';
		$before_title  = isset( $args['before_title'] ) ? $args['before_title'] : '';
		$after_title   = isset( $args['after_title'] ) ? $args['after_title'] : '';
		$after_widget  = isset( $args['after_widget'] ) ? $args['after_widget'] : '';

		/** This filter is documented in core/src/wp-includes/default-widgets.php */
		$title = apply_filters( 'widget_title', $instance['title'] );
		echo $before_widget; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		if ( $title ) {
			echo $before_title . $title . $after_title; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		if ( 'text' === $instance['format'] ) {
			echo '<ul>';
		}

		if ( 'posts' === $instance['display'] ) {
			$this->rss_link( 'posts', $instance );
		} elseif ( 'comments' === $instance['display'] ) {
			$this->rss_link( 'comments', $instance );
		} elseif ( 'posts-comments' === $instance['display'] ) {
			$this->rss_link( 'posts', $instance );
			$this->rss_link( 'comments', $instance );
		}

		if ( 'text' === $instance['format'] ) {
			echo '</ul>';
		}

		echo "\n" . $after_widget; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This action is documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'rss-links' );
	}

	/**
	 * Return an associative array of default values
	 * These values are used in new widgets as well as when sanitizing input.
	 *
	 * @return array Array of default values for the Widget's options
	 */
	public function defaults() {
		return array(
			'title'   => '',
			'display' => 'posts-comments',
			'format'  => 'text',
		);
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
		$instance = $old_instance;

		$instance['title']      = wp_filter_nohtml_kses( $new_instance['title'] );
		$instance['display']    = $new_instance['display'];
		$instance['format']     = $new_instance['format'];
		$instance['imagesize']  = $new_instance['imagesize'];
		$instance['imagecolor'] = $new_instance['imagecolor'];

		return $instance;
	}

	/**
	 * Back end widget form.
	 *
	 * @see WP_Widget::form()
	 *
	 * @param array $instance Previously saved values from database.
	 *
	 * @return string|void
	 */
	public function form( $instance ) {
		$instance = wp_parse_args( (array) $instance, $this->defaults() );

		$title       = stripslashes( $instance['title'] );
		$display     = $instance['display'];
		$format      = $instance['format'];
		$image_size  = isset( $instance['imagesize'] ) ? $instance['imagesize'] : 0;
		$image_color = isset( $instance['imagecolor'] ) ? $instance['imagecolor'] : 'red';

		echo '<p><label for="' . esc_attr( $this->get_field_id( 'title' ) ) . '">' . esc_html__( 'Title:', 'jetpack' ) . '
		<input class="widefat" id="' . esc_attr( $this->get_field_id( 'title' ) ) . '" name="' . esc_attr( $this->get_field_name( 'title' ) ) . '" type="text" value="' . esc_attr( $title ) . '" />
		</label></p>';

		$displays = array(
			'posts'          => __( 'Posts', 'jetpack' ),
			'comments'       => __( 'Comments', 'jetpack' ),
			'posts-comments' => __( 'Posts & Comments', 'jetpack' ),
		);
		echo '<p><label for="' . esc_attr( $this->get_field_id( 'display' ) ) . '">' . esc_html__( 'Feed(s) to Display:', 'jetpack' ) . '
		<select class="widefat" id="' . esc_attr( $this->get_field_id( 'display' ) ) . '" name="' . esc_attr( $this->get_field_name( 'display' ) ) . '">';
		foreach ( $displays as $display_option => $label ) {
			echo '<option value="' . esc_attr( $display_option ) . '"';
			if ( $display_option === $display ) {
				echo ' selected="selected"';
			}
			echo '>' . esc_html( $label ) . '</option>' . "\n";
		}
		echo '</select></label></p>';

		$formats = array(
			'text'       => __( 'Text Link', 'jetpack' ),
			'image'      => __( 'Image Link', 'jetpack' ),
			'text-image' => __( 'Text & Image Links', 'jetpack' ),
		);
		echo '<p><label for="' . esc_attr( $this->get_field_id( 'format' ) ) . '">' . esc_html_x( 'Format:', 'Noun', 'jetpack' ) . '
		<select class="widefat" id="' . esc_attr( $this->get_field_id( 'format' ) ) . '" name="' . esc_attr( $this->get_field_name( 'format' ) ) . '" onchange="if ( this.value == \'text\' ) jQuery( \'#' . esc_js( $this->get_field_id( 'image-settings' ) ) . '\' ).fadeOut(); else jQuery( \'#' . esc_js( $this->get_field_id( 'image-settings' ) ) . '\' ).fadeIn();">';
		foreach ( $formats as $format_option => $label ) {
			echo '<option value="' . esc_attr( $format_option ) . '"';
			if ( $format_option === $format ) {
				echo ' selected="selected"';
			}
			echo '>' . esc_html( $label ) . '</option>' . "\n";
		}
		echo '</select></label></p>';

		echo '<div id="' . esc_attr( $this->get_field_id( 'image-settings' ) ) . '"';
		if ( 'text' === $format ) {
			echo ' style="display: none;"';
		}
		echo '><h3>' . esc_html__( 'Image Settings:', 'jetpack' ) . '</h3>';

		$sizes = array(
			'small'  => __( 'Small', 'jetpack' ),
			'medium' => __( 'Medium', 'jetpack' ),
			'large'  => __( 'Large', 'jetpack' ),
		);
		echo '<p><label for="' . esc_attr( $this->get_field_id( 'imagesize' ) ) . '">' . esc_html__( 'Image Size:', 'jetpack' ) . '
		<select class="widefat" id="' . esc_attr( $this->get_field_id( 'imagesize' ) ) . '" name="' . esc_attr( $this->get_field_name( 'imagesize' ) ) . '">';
		foreach ( $sizes as $size => $label ) {
			echo '<option value="' . esc_attr( $size ) . '"';
			if ( $size === $image_size ) {
				echo ' selected="selected"';
			}
			echo '>' . esc_html( $label ) . '</option>' . "\n";
		}
		echo '</select></label></p>';

		$colors = array(
			'red'    => __( 'Red', 'jetpack' ),
			'orange' => __( 'Orange', 'jetpack' ),
			'green'  => __( 'Green', 'jetpack' ),
			'blue'   => __( 'Blue', 'jetpack' ),
			'purple' => __( 'Purple', 'jetpack' ),
			'pink'   => __( 'Pink', 'jetpack' ),
			'silver' => __( 'Silver', 'jetpack' ),
		);
		echo '<p><label for="' . esc_attr( $this->get_field_id( 'imagecolor' ) ) . '">' . esc_html__( 'Image Color:', 'jetpack' ) . '
		<select class="widefat" id="' . esc_attr( $this->get_field_id( 'imagecolor' ) ) . '" name="' . esc_attr( $this->get_field_name( 'imagecolor' ) ) . '">';
		foreach ( $colors as $color => $label ) {
			echo '<option value="' . esc_attr( $color ) . '"';
			if ( $color === $image_color ) {
				echo ' selected="selected"';
			}
			echo '>' . esc_html( $label ) . '</option>' . "\n";
		}
		echo '</select></label></p></div>';
	}

	/**
	 * Output a link with a link to the feed.
	 *
	 * @param string $type Widget type (posts or comments).
	 * @param array  $args Widget arguments.
	 */
	private function rss_link( $type, $args ) {
		if ( 'posts' === $type ) {
			$subscribe_to = esc_html__( 'Subscribe to posts', 'jetpack' );
			$link_text    = esc_html__( 'RSS - Posts', 'jetpack' );
			$rss_type     = 'rss2_url';
		} elseif ( 'comments' === $type ) {
			$subscribe_to = esc_html__( 'Subscribe to comments', 'jetpack' );
			$link_text    = esc_html__( 'RSS - Comments', 'jetpack' );
			$rss_type     = 'comments_rss2_url';
		}

		/**
		 * Filters the target link attribute for the RSS link in the RSS widget.
		 *
		 * @module widgets
		 *
		 * @since 3.4.0
		 *
		 * @param bool false Control whether the link should open in a new tab. Default to false.
		 */
		if ( apply_filters( 'jetpack_rsslinks_widget_target_blank', false ) ) {
			$link_target = '_blank';
		} else {
			$link_target = '_self';
		}

		$format = $args['format'];
		if ( 'image' === $format ) {
			$link_contents = $this->get_image_tag( $args );
		} elseif ( 'text-image' === $format ) {
			$link_contents = sprintf(
				'%1$s&nbsp;%2$s',
				$this->get_image_tag( $args ),
				$link_text
			);
		} elseif ( 'text' === $format ) {
			$link_contents = $link_text;
		}

		printf(
			'%1$s<a target="%3$s" href="%4$s" title="%5$s">%6$s</a>%2$s',
			'text' === $format ? '<li>' : '<p>', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'text' === $format ? '</li>' : '</p>', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			esc_attr( $link_target ),
			esc_url( get_bloginfo( $rss_type ) ),
			esc_attr( $subscribe_to ),
			$link_contents // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- we are escaping this above.
		);
	}

	/**
	 * Return an image tag for the RSS icon.
	 *
	 * @param array $args Widget arguments.
	 */
	private function get_image_tag( $args ) {
		$image_path = sprintf(
			'images/rss/%1$s-%2$s.png',
			$args['imagecolor'],
			$args['imagesize']
		);

		/**
		 * Filters the image used as RSS icon in the RSS widget.
		 *
		 * @module widgets
		 *
		 * @since 3.6.0
		 *
		 * @param string $var URL of RSS Widget icon.
		 */
		$image = apply_filters(
			'jetpack_rss_widget_icon',
			plugins_url( $image_path, dirname( __DIR__ ) )
		);

		return sprintf(
			'<img src="%1$s" alt="%2$s" />',
			esc_url( $image ),
			esc_attr__( 'RSS feed', 'jetpack' )
		);
	}
} // Class Jetpack_RSS_Links_Widget
