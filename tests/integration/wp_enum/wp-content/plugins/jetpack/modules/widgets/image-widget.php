<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Module Name: Image Widget
 * Module Description: Easily add images to your theme's sidebar.
 * Sort Order: 20
 * First Introduced: 1.2
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

add_action( 'widgets_init', 'jetpack_image_widget_init', 11 );
/**
 * Register the widget for use in Appearance -> Widgets
 */
function jetpack_image_widget_init() {
	if ( class_exists( 'WP_Widget_Media_Image' ) && Jetpack_Options::get_option( 'image_widget_migration' ) ) {
		return;
	}
	register_widget( 'Jetpack_Image_Widget' );
}

/**
 * Jetpack_Image_Widget main class.
 */
class Jetpack_Image_Widget extends WP_Widget {
	/**
	 * Register widget with WordPress.
	 */
	public function __construct() {
		parent::__construct(
			'image',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', esc_html__( 'Image', 'jetpack' ) ),
			array(
				'classname'                   => 'widget_image',
				'description'                 => __( 'Display an image in your sidebar', 'jetpack' ),
				'customize_selective_refresh' => true,
			)
		);

		if ( is_active_widget( false, false, $this->id_base ) || is_active_widget( false, false, 'monster' ) || is_customize_preview() ) {
			add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_style' ) );
		}
	}

	/**
	 * Loads file for front-end widget style.
	 *
	 * @uses wp_enqueue_style(), plugins_url()
	 */
	public function enqueue_style() {
		wp_enqueue_style( 'jetpack_image_widget', plugins_url( 'image-widget/style.css', __FILE__ ), array(), '20140808' );
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
		echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		$instance = wp_parse_args(
			$instance,
			array(
				'title'   => '',
				'img_url' => '',
			)
		);

		/** This filter is documented in core/src/wp-includes/default-widgets.php */
		$title = apply_filters( 'widget_title', $instance['title'] );
		if ( $title ) {
			echo $args['before_title'] . $title . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		if ( $instance['img_url'] ) {

			$output = '<img src="' . esc_url( $instance['img_url'] ) . '" ';

			if ( '' !== (string) $instance['alt_text'] ) {
				$output .= 'alt="' . esc_attr( $instance['alt_text'] ) . '" ';
			}
			if ( '' !== (string) $instance['img_title'] ) {
				$output .= 'title="' . esc_attr( $instance['img_title'] ) . '" ';
			}
			if ( '' !== (string) $instance['caption'] ) {
				$output .= 'class="align' . esc_attr( $instance['align'] ) . '" ';
			}
			if ( '' !== (string) $instance['img_width'] ) {
				$output .= 'width="' . esc_attr( $instance['img_width'] ) . '" ';
			}
			if ( '' !== (string) $instance['img_height'] ) {
				$output .= 'height="' . esc_attr( $instance['img_height'] ) . '" ';
			}
			$output .= '/>';

			if ( class_exists( 'Jetpack_Photon' ) && Jetpack::is_module_active( 'photon' ) ) {
				$output = Jetpack_Photon::filter_the_content( $output );
			}

			if ( $instance['link'] ) {
				$target = ! empty( $instance['link_target_blank'] )
					? 'target="_blank"'
					: '';
				$output = '<a ' . $target . ' href="' . esc_url( $instance['link'] ) . '">' . $output . '</a>';
			}
			if ( '' !== (string) $instance['caption'] ) {
				/** This filter is documented in core/src/wp-includes/default-widgets.php */
				$caption   = apply_filters( 'widget_text', $instance['caption'] );
				$img_width = ( ! empty( $instance['img_width'] ) ? 'style="width: ' . esc_attr( $instance['img_width'] ) . 'px"' : '' );
				$output    = '<figure ' . $img_width . ' class="wp-caption align' . esc_attr( $instance['align'] ) . '">
					' . $output . '
					<figcaption class="wp-caption-text">' . $caption . '</figcaption>
				</figure>'; // wp_kses_post caption on update.
			}
			echo '<div class="jetpack-image-container">' . do_shortcode( $output ) . '</div>';
		} elseif ( current_user_can( 'edit_theme_options' ) ) {
			echo '<p>' . wp_kses(
				sprintf(
					/* translators: %s link to the widget settings page. */
					__( 'Image missing or invalid URL. Please check the Image widget URL in your <a href="%s">widget settings</a>.', 'jetpack' ),
					admin_url( 'widgets.php' )
				),
				array(
					'a' => array(
						'href' => array(),
					),
				)
			) . '</p>';
		}

		echo "\n" . $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This action is documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'image' );
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
	public function update( $new_instance, $old_instance ) {
		$allowed_caption_html = array(
			'a'      => array(
				'href'  => array(),
				'title' => array(),
			),
			'b'      => array(),
			'em'     => array(),
			'i'      => array(),
			'p'      => array(),
			'strong' => array(),
		);

		$instance = $old_instance;

		$instance['title']             = wp_strip_all_tags( $new_instance['title'] );
		$instance['img_url']           = esc_url( trim( $new_instance['img_url'] ) );
		$instance['alt_text']          = wp_strip_all_tags( $new_instance['alt_text'] );
		$instance['img_title']         = wp_strip_all_tags( $new_instance['img_title'] );
		$instance['caption']           = wp_kses( stripslashes( $new_instance['caption'] ), $allowed_caption_html );
		$instance['align']             = $new_instance['align'];
		$instance['link']              = esc_url( trim( $new_instance['link'] ) );
		$instance['link_target_blank'] = isset( $new_instance['link_target_blank'] ) ? (bool) $new_instance['link_target_blank'] : false;

		$new_img_width  = absint( $new_instance['img_width'] );
		$new_img_height = absint( $new_instance['img_height'] );

		if ( ! empty( $instance['img_url'] ) && 0 === $new_img_width && 0 === $new_img_height ) {
			// Download the url to a local temp file and then process it with getimagesize so we can optimize browser layout.
			$tmp_file = download_url( $instance['img_url'], 10 );
			if ( ! is_wp_error( $tmp_file ) ) {
				$size = getimagesize( $tmp_file );

				$width                 = $size[0];
				$instance['img_width'] = absint( $width );

				$height                 = $size[1];
				$instance['img_height'] = absint( $height );

				wp_delete_file( $tmp_file );
			} else {
				$instance['img_width']  = $new_img_width;
				$instance['img_height'] = $new_img_height;
			}
		} else {
			$instance['img_width']  = $new_img_width;
			$instance['img_height'] = $new_img_height;
		}

		return $instance;
	}

	/**
	 * Back end widget form.
	 *
	 * @see WP_Widget::form()
	 *
	 * @param array $instance Previously saved values from database.
	 */
	public function form( $instance ) {
		// Defaults.
		$instance = wp_parse_args(
			(array) $instance,
			array(
				'title'             => '',
				'img_url'           => '',
				'alt_text'          => '',
				'img_title'         => '',
				'caption'           => '',
				'align'             => 'none',
				'img_width'         => '',
				'img_height'        => '',
				'link'              => '',
				'link_target_blank' => false,
			)
		);

		$title             = esc_attr( $instance['title'] );
		$img_url           = esc_url( $instance['img_url'], null, 'display' );
		$alt_text          = esc_attr( $instance['alt_text'] );
		$img_title         = esc_attr( $instance['img_title'] );
		$caption           = esc_textarea( $instance['caption'] );
		$align             = esc_attr( $instance['align'] );
		$img_width         = esc_attr( $instance['img_width'] );
		$img_height        = esc_attr( $instance['img_height'] );
		$link_target_blank = checked( $instance['link_target_blank'], true, false );

		$link = esc_url( $instance['link'], null, 'display' );

		echo '<p><label for="' . esc_attr( $this->get_field_id( 'title' ) ) . '">' . esc_html__( 'Widget title:', 'jetpack' ) . '
			<input class="widefat" id="' . esc_attr( $this->get_field_id( 'title' ) ) . '" name="' . esc_attr( $this->get_field_name( 'title' ) ) . '" type="text" value="' . esc_attr( $title ) . '" />
			</label></p>
			<p><label for="' . esc_attr( $this->get_field_id( 'img_url' ) ) . '">' . esc_html__( 'Image URL:', 'jetpack' ) . '
			<input class="widefat" id="' . esc_attr( $this->get_field_id( 'img_url' ) ) . '" name="' . esc_attr( $this->get_field_name( 'img_url' ) ) . '" type="text" value="' . esc_attr( $img_url ) . '" />
			</label></p>
			<p><label for="' . esc_attr( $this->get_field_id( 'alt_text' ) ) . '">' . esc_html__( 'Alternate text:', 'jetpack' ) . '  <a href="https://support.wordpress.com/widgets/image-widget/#image-widget-alt-text" target="_blank">( ? )</a>
			<input class="widefat" id="' . esc_attr( $this->get_field_id( 'alt_text' ) ) . '" name="' . esc_attr( $this->get_field_name( 'alt_text' ) ) . '" type="text" value="' . esc_attr( $alt_text ) . '" />
			</label></p>
			<p><label for="' . esc_attr( $this->get_field_id( 'img_title' ) ) . '">' . esc_html__( 'Image title:', 'jetpack' ) . ' <a href="https://support.wordpress.com/widgets/image-widget/#image-widget-title" target="_blank">( ? )</a>
			<input class="widefat" id="' . esc_attr( $this->get_field_id( 'img_title' ) ) . '" name="' . esc_attr( $this->get_field_name( 'img_title' ) ) . '" type="text" value="' . esc_attr( $img_title ) . '" />
			</label></p>
			<p><label for="' . esc_attr( $this->get_field_id( 'caption' ) ) . '">' . esc_html__( 'Caption:', 'jetpack' ) . ' <a href="https://support.wordpress.com/widgets/image-widget/#image-widget-caption" target="_blank">( ? )</a>
			<textarea class="widefat" id="' . esc_attr( $this->get_field_id( 'caption' ) ) . '" name="' . esc_attr( $this->get_field_name( 'caption' ) ) . '" rows="2" cols="20">' . esc_textarea( $caption ) . '</textarea>
			</label></p>';

		$alignments = array(
			'none'   => __( 'None', 'jetpack' ),
			'left'   => __( 'Left', 'jetpack' ),
			'center' => __( 'Center', 'jetpack' ),
			'right'  => __( 'Right', 'jetpack' ),
		);
		echo '<p><label for="' . esc_attr( $this->get_field_id( 'align' ) ) . '">' . esc_html__( 'Image Alignment:', 'jetpack' ) . '
			<select id="' . esc_attr( $this->get_field_id( 'align' ) ) . '" name="' . esc_attr( $this->get_field_name( 'align' ) ) . '">';
		foreach ( $alignments as $alignment => $alignment_name ) {
			echo '<option value="' . esc_attr( $alignment ) . '" ';
			if ( $alignment === $align ) {
				echo 'selected="selected" ';
			}
			echo '>' . esc_html( $alignment_name ) . "</option>\n";
		}
		echo '</select></label></p>';

		echo '<p><label for="' . esc_attr( $this->get_field_id( 'img_width' ) ) . '">' . esc_html__( 'Width in pixels:', 'jetpack' ) . '
		<input size="3" id="' . esc_attr( $this->get_field_id( 'img_width' ) ) . '" name="' . esc_attr( $this->get_field_name( 'img_width' ) ) . '" type="text" value="' . esc_attr( $img_width ) . '" />
		</label>
		<label for="' . esc_attr( $this->get_field_id( 'img_height' ) ) . '">' . esc_html__( 'Height in pixels:', 'jetpack' ) . '
		<input size="3" id="' . esc_attr( $this->get_field_id( 'img_height' ) ) . '" name="' . esc_attr( $this->get_field_name( 'img_height' ) ) . '" type="text" value="' . esc_attr( $img_height ) . '" />
		</label><br />
		<small>' . esc_html__( 'If empty, we will attempt to determine the image size.', 'jetpack' ) . '</small></p>
		<p><label for="' . esc_attr( $this->get_field_id( 'link' ) ) . '">' . esc_html__( 'Link URL (when the image is clicked):', 'jetpack' ) . '
		<input class="widefat" id="' . esc_attr( $this->get_field_id( 'link' ) ) . '" name="' . esc_attr( $this->get_field_name( 'link' ) ) . '" type="text" value="' . esc_attr( $link ) . '" />
		</label>
		<label for="' . esc_attr( $this->get_field_id( 'link_target_blank' ) ) . '">
		<input type="checkbox" name="' . esc_attr( $this->get_field_name( 'link_target_blank' ) ) . '" id="' . esc_attr( $this->get_field_id( 'link_target_blank' ) ) . '" value="1"' . esc_attr( $link_target_blank ) . '/>
		' . esc_html__( 'Open link in a new window/tab', 'jetpack' ) . '
		</label></p>';
	}
} // Class Jetpack_Image_Widget
