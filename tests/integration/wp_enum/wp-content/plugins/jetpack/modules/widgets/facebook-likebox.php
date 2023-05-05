<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

add_action( 'widgets_init', 'jetpack_facebook_likebox_init' );
/**
 * Register the widget for use in Appearance -> Widgets
 */
function jetpack_facebook_likebox_init() {
	register_widget( 'WPCOM_Widget_Facebook_LikeBox' );
}

/**
 * Facebook Page Plugin (formerly known as the Like Box)
 * Display a Facebook Page Plugin as a widget (replaces the old like box plugin)
 * https://developers.facebook.com/docs/plugins/page-plugin
 */
class WPCOM_Widget_Facebook_LikeBox extends WP_Widget {
	/**
	 * Default height.
	 *
	 * @var int
	 */
	private $default_height = 580;

	/**
	 * Default width.
	 *
	 * @var int
	 */
	private $default_width = 340;

	/**
	 * Max width.
	 *
	 * @var int
	 */
	private $max_width = 500;

	/**
	 * Min width.
	 *
	 * @var int
	 */
	private $min_width = 180;

	/**
	 * Max height.
	 *
	 * @var int
	 */
	private $max_height = 9999;

	/**
	 * Min height/
	 *
	 * @var int
	 */
	private $min_height = 130;

	/**
	 * WPCOM_Widget_Facebook_LikeBox constructor.
	 */
	public function __construct() {
		parent::__construct(
			'facebook-likebox',
			/**
			 * Filter the name of a widget included in the Extra Sidebar Widgets module.
			 *
			 * @module widgets
			 *
			 * @since 2.1.2
			 *
			 * @param string $widget_name Widget title.
			 */
			apply_filters( 'jetpack_widget_name', __( 'Facebook Page Plugin', 'jetpack' ) ),
			array(
				'classname'                   => 'widget_facebook_likebox',
				'description'                 => __( 'Use the Facebook Page Plugin to connect visitors to your Facebook Page', 'jetpack' ),
				'customize_selective_refresh' => true,
			)
		);

		if ( is_active_widget( false, false, $this->id_base ) || is_active_widget( false, false, 'monster' ) || is_customize_preview() ) {
			add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		}
	}

	/**
	 * Enqueue scripts.
	 */
	public function enqueue_scripts() {
		wp_enqueue_script( 'jetpack-facebook-embed' );
		wp_enqueue_style(
			'jetpack_facebook_likebox',
			plugins_url( 'facebook-likebox/style.css', __FILE__ ),
			array(),
			JETPACK__VERSION
		);
		// Inline styles. @see wp_maybe_inline_styles()
		wp_style_add_data( 'jetpack_facebook_likebox', 'path', plugin_dir_path( __FILE__ ) . 'facebook-likebox/style.css' );
	}

	/**
	 * Display the widget.
	 *
	 * @param array $args Display arguments including before_title, after_title, before_widget, and after_widget.
	 * @param array $instance The settings for the particular instance of the widget.
	 */
	public function widget( $args, $instance ) {
		$before_widget = isset( $args['before_widget'] ) ? $args['before_widget'] : '';
		$before_title  = isset( $args['before_title'] ) ? $args['before_title'] : '';
		$after_title   = isset( $args['after_title'] ) ? $args['after_title'] : '';
		$after_widget  = isset( $args['after_widget'] ) ? $args['after_widget'] : '';
		$like_args     = $this->get_default_args();

		if ( isset( $instance['like_args'] ) ) {
			$like_args = $this->normalize_facebook_args( $instance['like_args'] );
		}

		if ( empty( $like_args['href'] ) || ! $this->is_valid_facebook_url( $like_args['href'] ) ) {
			if ( current_user_can( 'edit_theme_options' ) ) {
				echo $before_widget; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

				$error_link = wp_kses(
					sprintf(
						/* translators: %s: link to widgets administration screen. */
						__( 'It looks like your Facebook URL is incorrectly configured. Please check it in your <a href="%1$s">widget settings</a>.', 'jetpack' ),
						esc_url( admin_url( 'widgets.php' ) )
					),
					array( 'a' => array( 'href' => array() ) )
				);
				printf(
					'<p>%s</p>',
					$error_link // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				);

				echo $after_widget; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			echo '<!-- Invalid Facebook Page URL -->';
			return;
		}

		/** This filter is documented in core/src/wp-includes/default-widgets.php */
		$title    = apply_filters( 'widget_title', $instance['title'] );
		$page_url = set_url_scheme( $like_args['href'], 'https' );

		$like_args['show_faces']   = (bool) $like_args['show_faces'] ? 'true' : 'false';
		$like_args['stream']       = (bool) $like_args['stream'] ? 'timeline' : 'false';
		$like_args['cover']        = (bool) $like_args['cover'] ? 'false' : 'true';
		$like_args['small_header'] = (bool) $like_args['small_header'] ? 'true' : 'false';

		/**
		 * Filter Facebook Likebox's widget call to action button
		 *
		 * @module widgets
		 *
		 * @since 8.4.0
		 *
		 * @param bool True value hides the call to action button
		 */
		$hide_cta = apply_filters( 'jetpack_facebook_likebox_hide_cta', false );

		echo $before_widget; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		if ( ! empty( $title ) ) :
			echo $before_title; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

			$likebox_widget_title = '<a href="' . esc_url( $page_url ) . '">' . $title . '</a>';
			/**
			 * Filter Facebook Likebox's widget title.
			 *
			 * @module widgets
			 *
			 * @since 3.3.0
			 *
			 * @param string $likebox_widget_title Likebox Widget title (including a link to the Page URL).
			 * @param string $title Widget title as set in the widget settings.
			 * @param string $page_url Facebook Page URL.
			 */
			$likebox_widget_title = apply_filters( 'jetpack_facebook_likebox_title', $likebox_widget_title, $title, $page_url );

			echo wp_kses(
				$likebox_widget_title,
				array( 'a' => array( 'href' => array() ) )
			);

			echo $after_title; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		endif;

		?>
		<div id="fb-root"></div>
		<div class="fb-page" data-href="<?php echo esc_url( $page_url ); ?>" data-width="<?php echo (int) $like_args['width']; ?>"  data-height="<?php echo (int) $like_args['height']; ?>" data-hide-cover="<?php echo esc_attr( $like_args['cover'] ); ?>" data-show-facepile="<?php echo esc_attr( $like_args['show_faces'] ); ?>" data-tabs="<?php echo esc_attr( $like_args['stream'] ); ?>" data-hide-cta="<?php echo esc_attr( $hide_cta ? 'true' : 'false' ); ?>" data-small-header="<?php echo esc_attr( $like_args['small_header'] ); ?>">
		<div class="fb-xfbml-parse-ignore"><blockquote cite="<?php echo esc_url( $page_url ); ?>"><a href="<?php echo esc_url( $page_url ); ?>"><?php echo esc_html( $title ); ?></a></blockquote></div>
		</div>
		<?php
		wp_enqueue_script( 'jetpack-facebook-embed' );

		echo $after_widget; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This action is documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'facebook-likebox' );
	}

	/**
	 * Update widget.
	 *
	 * @see WP_Widget::update()
	 *
	 * @param array $new_instance New widget instance data.
	 * @param array $old_instance Old widget instance data.
	 */
	public function update( $new_instance, $old_instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$instance = array();

		$instance['title'] = trim( wp_strip_all_tags( stripslashes( $new_instance['title'] ) ) );

		// Set up widget values.
		$instance['like_args'] = array(
			'href'         => trim( wp_strip_all_tags( stripslashes( $new_instance['href'] ) ) ),
			'width'        => (int) $new_instance['width'],
			'height'       => (int) $new_instance['height'],
			'show_faces'   => isset( $new_instance['show_faces'] ),
			'stream'       => isset( $new_instance['stream'] ),
			'cover'        => isset( $new_instance['cover'] ),
			'small_header' => isset( $new_instance['small_header'] ),
		);

		$instance['like_args'] = $this->normalize_facebook_args( $instance['like_args'] );

		// Include the new instance's args in the array's top level to support updating from the Widgets page.
		$instance = array_merge( $instance, array_intersect_key( $instance['like_args'], $new_instance ) );

		return $instance;
	}

	/**
	 * Outputs the widget settings form.
	 *
	 * @param array $instance Current settings.
	 */
	public function form( $instance ) {
		$instance  = wp_parse_args(
			(array) $instance,
			array(
				'title'     => '',
				'like_args' => $this->get_default_args(),
			)
		);
		$like_args = $this->normalize_facebook_args( $instance['like_args'] );
		?>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>">
				<?php esc_html_e( 'Title', 'jetpack' ); ?>
				<input type="text" name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>" value="<?php echo esc_attr( $instance['title'] ); ?>" class="widefat" />
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'href' ) ); ?>">
				<?php esc_html_e( 'Facebook Page URL', 'jetpack' ); ?>
				<input type="text" name="<?php echo esc_attr( $this->get_field_name( 'href' ) ); ?>" id="<?php echo esc_attr( $this->get_field_id( 'href' ) ); ?>" value="<?php echo esc_url( $like_args['href'] ); ?>" class="widefat" />
				<br />
				<small><?php esc_html_e( 'The widget only works with Facebook Pages.', 'jetpack' ); ?></small>
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'width' ) ); ?>">
				<?php esc_html_e( 'Width in pixels', 'jetpack' ); ?>
				<input type="number" class="smalltext" min="<?php echo esc_attr( $this->min_width ); ?>" max="<?php echo esc_attr( $this->max_width ); ?>" maxlength="3" name="<?php echo esc_attr( $this->get_field_name( 'width' ) ); ?>" id="<?php echo esc_attr( $this->get_field_id( 'width' ) ); ?>" value="<?php echo esc_attr( $like_args['width'] ); ?>" style="text-align: center;" />
				<small>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s is the minimum pixel width */
							__( 'Minimum: %s', 'jetpack' ),
							$this->min_width
						)
					);
					echo ' / ';
					echo esc_html(
						sprintf(
							/* translators: %s is the maximum pixel width */
							__( 'Maximum: %s', 'jetpack' ),
							$this->max_width
						)
					);
					?>
				</small>
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'height' ) ); ?>">
				<?php esc_html_e( 'Height in pixels', 'jetpack' ); ?>
				<input type="number" class="smalltext" min="<?php echo esc_attr( $this->min_height ); ?>" max="<?php echo esc_attr( $this->max_height ); ?>" maxlength="3" name="<?php echo esc_attr( $this->get_field_name( 'height' ) ); ?>" id="<?php echo esc_attr( $this->get_field_id( 'height' ) ); ?>" value="<?php echo esc_attr( $like_args['height'] ); ?>" style="text-align: center;" />
				<small>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s is the minimum pixel height */
							__( 'Minimum: %s', 'jetpack' ),
							$this->min_height
						)
					);
					echo ' / ';
					echo esc_html(
						sprintf(
							/* translators: %s is the maximum pixel height */
							__( 'Maximum: %s', 'jetpack' ),
							$this->max_height
						)
					);
					?>
				</small>
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'show_faces' ) ); ?>">
				<input type="checkbox" name="<?php echo esc_attr( $this->get_field_name( 'show_faces' ) ); ?>" id="<?php echo esc_attr( $this->get_field_id( 'show_faces' ) ); ?>" <?php checked( $like_args['show_faces'] ); ?> />
				<?php esc_html_e( 'Show Faces', 'jetpack' ); ?>
				<br />
				<small><?php esc_html_e( 'Show profile photos in the plugin.', 'jetpack' ); ?></small>
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'stream' ) ); ?>">
				<input type="checkbox" name="<?php echo esc_attr( $this->get_field_name( 'stream' ) ); ?>" id="<?php echo esc_attr( $this->get_field_id( 'stream' ) ); ?>" <?php checked( $like_args['stream'] ); ?> />
				<?php esc_html_e( 'Show Timeline', 'jetpack' ); ?>
				<br />
				<small><?php esc_html_e( 'Show Page Posts.', 'jetpack' ); ?></small>
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'cover' ) ); ?>">
				<input type="checkbox" name="<?php echo esc_attr( $this->get_field_name( 'cover' ) ); ?>" id="<?php echo esc_attr( $this->get_field_id( 'cover' ) ); ?>" <?php checked( $like_args['cover'] ); ?> />
				<?php esc_html_e( 'Show Cover Photo', 'jetpack' ); ?>
				<br />
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'small_header' ) ); ?>">
				<input type="checkbox" name="<?php echo esc_attr( $this->get_field_name( 'small_header' ) ); ?>" id="<?php echo esc_attr( $this->get_field_id( 'small_header' ) ); ?>" <?php checked( $like_args['small_header'] ); ?> />
				<?php esc_html_e( 'Use Small Header', 'jetpack' ); ?>
				<br />
			</label>
		</p>

		<?php
	}

	/**
	 * Facebook Likebox default options.
	 */
	public function get_default_args() {
		$defaults = array(
			'href'         => '',
			'width'        => $this->default_width,
			'height'       => $this->default_height,
			'show_faces'   => 'true',
			'stream'       => '',
			'cover'        => 'true',
			'small_header' => '',
		);

		/**
		 * Filter Facebook Likebox default options.
		 *
		 * @module widgets
		 *
		 * @since 1.3.1
		 *
		 * @param array $defaults Array of default options.
		 */
		return apply_filters( 'jetpack_facebook_likebox_defaults', $defaults );
	}

	/**
	 * Normalize the Facebook Likebox options.
	 *
	 * @param array $args Array of arguments.
	 */
	public function normalize_facebook_args( $args ) {
		$args = wp_parse_args( (array) $args, $this->get_default_args() );

		// Validate the Facebook Page URL.
		if ( $this->is_valid_facebook_url( $args['href'] ) ) {
			$temp         = explode( '?', $args['href'] );
			$args['href'] = str_replace( array( 'http://facebook.com', 'https://facebook.com' ), array( 'http://www.facebook.com', 'https://www.facebook.com' ), $temp[0] );
		} else {
			$args['href'] = '';
		}

		$args['width']        = $this->normalize_int_value( (int) $args['width'], $this->max_width, $this->min_width );
		$args['height']       = $this->normalize_int_value( (int) $args['height'], $this->max_height, $this->min_height );
		$args['show_faces']   = (bool) $args['show_faces'];
		$args['stream']       = (bool) $args['stream'];
		$args['cover']        = (bool) $args['cover'];
		$args['small_header'] = (bool) $args['small_header'];

		// The height used to be dependent on other widget settings
		// If the user changes those settings but doesn't customize the height,
		// let's intelligently assign a new height.
		if ( in_array( $args['height'], array( 580, 110, 432 ), true ) ) {
			if ( $args['show_faces'] && $args['stream'] ) {
				$args['height'] = 580;
			} elseif ( ! $args['show_faces'] && ! $args['stream'] ) {
				$args['height'] = 130;
			} else {
				$args['height'] = 432;
			}
		}

		return $args;
	}

	/**
	 * Check if URL is a valid Facebook Page URL.
	 *
	 * @param string $url URL to check.
	 */
	public function is_valid_facebook_url( $url ) {
		return ( false !== strpos( $url, 'facebook.com' ) ) ? true : false;
	}

	/**
	 * Normalize an integer value within a given range.
	 *
	 * @param int $value Value to normalize.
	 * @param int $max Maximum value.
	 * @param int $min Minimum value.
	 *
	 * @return int Normalized value.
	 */
	public function normalize_int_value( $value, $max = 0, $min = 0 ) {
		$value = (int) $value;

		if ( $value > $max ) {
			$value = $max;
		} elseif ( $value < $min ) {
			$value = $min;
		}

		return (int) $value;
	}
}
