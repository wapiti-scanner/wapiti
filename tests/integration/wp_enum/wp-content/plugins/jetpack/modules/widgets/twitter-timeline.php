<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Twitter Timeline Widget.
 *
 * Based on Evolution Twitter Timeline
 * (https://wordpress.org/extend/plugins/evolution-twitter-timeline/)
 * For details on Twitter Timelines see:
 *  - https://twitter.com/settings/widgets
 *  - https://dev.twitter.com/docs/embedded-timelines
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Redirect;

/**
 * Register the widget for use in Appearance -> Widgets
 */
function jetpack_twitter_timeline_widget_init() {
	register_widget( 'Jetpack_Twitter_Timeline_Widget' );
}
add_action( 'widgets_init', 'jetpack_twitter_timeline_widget_init' );

/**
 * Widget class.
 */
class Jetpack_Twitter_Timeline_Widget extends WP_Widget {
	/**
	 * Register widget with WordPress.
	 */
	public function __construct() {
		parent::__construct(
			'twitter_timeline',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', esc_html__( 'Twitter Timeline', 'jetpack' ) ),
			array(
				'classname'                   => 'widget_twitter_timeline',
				'description'                 => __( 'Display an official Twitter Embedded Timeline widget.', 'jetpack' ),
				'customize_selective_refresh' => true,
			)
		);

		if ( is_active_widget( false, false, $this->id_base ) || is_active_widget( false, false, 'monster' ) || is_customize_preview() ) {
			add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		}

		add_action( 'admin_enqueue_scripts', array( $this, 'admin_scripts' ) );
		add_filter( 'widget_types_to_hide_from_legacy_widget_block', array( $this, 'hide_widget_in_block_editor' ) );
	}

	/**
	 * Remove the "Twitter Timeline" widget from the Legacy Widget block
	 *
	 * @param array $widget_types List of widgets that are currently removed from the Legacy Widget block.
	 * @return array $widget_types New list of widgets that will be removed.
	 */
	public function hide_widget_in_block_editor( $widget_types ) {
		$widget_types[] = 'twitter_timeline';
		return $widget_types;
	}

	/**
	 * Enqueue scripts.
	 */
	public function enqueue_scripts() {
		if ( ! class_exists( 'Jetpack_AMP_Support' ) || ! Jetpack_AMP_Support::is_amp_request() ) {
			wp_enqueue_script( 'jetpack-twitter-timeline' );
		}
	}

	/**
	 * Enqueue script to improve admin UI
	 *
	 * @param string $hook Page hook.
	 */
	public function admin_scripts( $hook ) {
		// This is still 'widgets.php' when managing widgets via the Customizer.
		if ( 'widgets.php' === $hook ) {
			wp_enqueue_script(
				'twitter-timeline-admin',
				Assets::get_file_url_for_environment(
					'_inc/build/widgets/twitter-timeline-admin.min.js',
					'modules/widgets/twitter-timeline-admin.js'
				),
				array( 'jquery' ),
				JETPACK__VERSION,
				true
			);
		}
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
		$output = '';

		// Twitter deprecated `data-widget-id` on 2018-05-25,
		// with cease support deadline on 2018-07-27.
		if ( isset( $instance['type'] ) && 'widget-id' === $instance['type'] ) {
			if ( current_user_can( 'edit_theme_options' ) ) {
				$output .= $args['before_widget']
				. $args['before_title'] . esc_html__( 'Twitter Timeline', 'jetpack' ) . $args['after_title']
				. '<p>' . esc_html__( "The Twitter Timeline widget can't display tweets based on searches or hashtags. To display a simple list of tweets instead, change the Widget ID to a Twitter username. Otherwise, delete this widget.", 'jetpack' ) . '</p>'
				. '<p>' . esc_html__( '(Only administrators will see this message.)', 'jetpack' ) . '</p>'
				. $args['after_widget'];
			}

			echo $output; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			return;
		}

		$instance['lang'] = substr( strtoupper( get_locale() ), 0, 2 );

		$output .= $args['before_widget'];

		$title = isset( $instance['title'] ) ? $instance['title'] : '';

		/** This filter is documented in core/src/wp-includes/default-widgets.php */
		$title = apply_filters( 'widget_title', $title );
		if ( ! empty( $title ) ) {
			$output .= $args['before_title'] . $title . $args['after_title'];
		}

		$possible_data_attribs = array(
			'width',
			'height',
			'theme',
			'border-color',
			'tweet-limit',
			'lang',
		);
		$data_attrs            = '';
		foreach ( $possible_data_attribs as $att ) {
			if ( ! empty( $instance[ $att ] ) && ! is_array( $instance[ $att ] ) ) {
				$data_attrs .= ' data-' . esc_attr( $att ) . '="' . esc_attr( $instance[ $att ] ) . '"';
			}
		}

		/** This filter is documented in modules/shortcodes/tweet.php */
		$partner = apply_filters( 'jetpack_twitter_partner_id', 'jetpack' );
		if ( ! empty( $partner ) ) {
			$data_attrs .= ' data-partner="' . esc_attr( $partner ) . '"';
		}

		/**
		 * Allow the activation of Do Not Track for the Twitter Timeline Widget.
		 *
		 * @see https://developer.twitter.com/en/docs/twitter-for-websites/timelines/guides/parameter-reference.html
		 *
		 * @module widgets
		 *
		 * @since 6.9.0
		 *
		 * @param bool false Should the Twitter Timeline use the DNT attribute? Default to false.
		 */
		$dnt = apply_filters( 'jetpack_twitter_timeline_default_dnt', false );
		if ( true === $dnt ) {
			$data_attrs .= ' data-dnt="true"';
		}

		if ( ! empty( $instance['chrome'] ) && is_array( $instance['chrome'] ) ) {
			$data_attrs .= ' data-chrome="' . esc_attr( join( ' ', $instance['chrome'] ) ) . '"';
		}

		$timeline_placeholder = __( 'My Tweets', 'jetpack' );

		/**
		 * Filter the Timeline placeholder text.
		 *
		 * @module widgets
		 *
		 * @since 3.4.0
		 *
		 * @param string $timeline_placeholder Timeline placeholder text.
		 */
		$timeline_placeholder = apply_filters( 'jetpack_twitter_timeline_placeholder', $timeline_placeholder );

		$type      = ( isset( $instance['type'] ) ? $instance['type'] : '' );
		$widget_id = ( isset( $instance['widget-id'] ) ? $instance['widget-id'] : '' );

		if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
			$width   = ! empty( $instance['width'] ) ? $instance['width'] : 600;
			$height  = ! empty( $instance['height'] ) ? $instance['height'] : 480;
			$output .= '<amp-twitter' . $data_attrs . ' layout="responsive" data-timeline-source-type="profile" data-timeline-screen-name="' . esc_attr( $widget_id ) . '" width="' . absint( $width ) . '" height="' . absint( $height ) . '">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$output .= esc_html( $timeline_placeholder ) . '</amp-twitter>';

			echo $output . $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			return;
		}

		// Start tag output
		// This tag is transformed into the widget markup by Twitter's
		// widgets.js code.
		$output .= '<a class="twitter-timeline"' . $data_attrs; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		switch ( $type ) {
			case 'profile':
				$output .= ' href="https://twitter.com/' . esc_attr( $widget_id ) . '"';
				break;
			case 'widget-id':
			default:
				$output .= ' data-widget-id="' . esc_attr( $widget_id ) . '"';
				break;
		}
		$output .= ' href="https://twitter.com/' . esc_attr( $widget_id ) . '"';

		// End tag output.
		$output .= '>';

		$output .= esc_html( $timeline_placeholder ) . '</a>';

		// End tag output.

		echo $output . $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This action is documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'twitter_timeline' );
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
		$instance = array();

		$instance['title'] = sanitize_text_field( $new_instance['title'] );

		$width = (int) $new_instance['width'];
		if ( $width ) {
			// From publish.twitter.com: 220 <= width <= 1200.
			$instance['width'] = min( max( $width, 220 ), 1200 );
		} else {
			// Set default width value to minimum.
			$instance['width'] = 220;
		}

		$tweet_display             = sanitize_text_field( $new_instance['tweet-display'] );
		$instance['tweet-display'] = $tweet_display;
		/**
		 * A timeline with a specified limit is expanded to the height of those Tweets.
		 * The specified height value no longer applies, so reject the height value
		 * when a valid limit is set: a widget attempting to save both limit 5 and
		 * height 400 would be saved with just limit 5.
		 * So if the tweet display option is set to 'dynamic' the limit will be unset and we'll
		 * take into account the height value.
		 * If the tweet display option is set to 'fixed' the height will be unset and we'll
		 * take into account the limit value.
		 */
		$instance['height']      = '';
		$instance['tweet-limit'] = null;

		switch ( $tweet_display ) {
			case 'dynamic':
				$height = (int) $new_instance['height'];
				// From publish.twitter.com: height >= 200.
				$instance['height'] = max( $height, 200 );
				break;
			case 'fixed':
				$tweet_limit = (int) $new_instance['tweet-limit'];
				// From publish.twitter.com: 1 >= tweet-limit >= 20.
				$instance['tweet-limit'] = min( max( $tweet_limit, 1 ), 20 );
				break;
		}

		// If they entered something that might be a full URL, try to parse it out.
		if ( is_string( $new_instance['widget-id'] ) ) {
			if ( preg_match(
				'#https?://twitter\.com/settings/widgets/(\d+)#s',
				$new_instance['widget-id'],
				$matches
			) ) {
				$new_instance['widget-id'] = $matches[1];
			}
		}

		$instance['widget-id'] = sanitize_text_field( $new_instance['widget-id'] );

		$new_border_color = sanitize_hex_color( $new_instance['border-color'] );
		if ( ! empty( $new_border_color ) ) {
			$instance['border-color'] = $new_border_color;
		}

		$instance['type'] = 'profile';

		$instance['theme'] = 'light';
		if ( in_array( $new_instance['theme'], array( 'light', 'dark' ), true ) ) {
			$instance['theme'] = $new_instance['theme'];
		}

		$instance['chrome'] = array();
		$chrome_settings    = array(
			'noheader',
			'nofooter',
			'noborders',
			'transparent',
			'noscrollbar',
		);

		foreach ( $chrome_settings as $chrome ) {
			switch ( $chrome ) {
				case 'noheader':
				case 'nofooter':
				case 'noborders':
				case 'noscrollbar':
					if ( ! isset( $new_instance['chrome'] ) || ! in_array( $chrome, $new_instance['chrome'], true ) ) {
						$instance['chrome'][] = $chrome;
					}
					break;
				default:
					if ( isset( $new_instance['chrome'] ) && in_array( $chrome, $new_instance['chrome'], true ) ) {
						$instance['chrome'][] = $chrome;
					}
					break;
			}
		}

		return $instance;
	}

	/**
	 * Returns a link to the documentation for a feature of this widget on
	 * Jetpack or WordPress.com.
	 *
	 * @param string $hash anchor to potentially append to URL to target specific paragraph in page.
	 */
	public function get_docs_link( $hash = '' ) {
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$base_url = 'https://wordpress.com/support/widgets/twitter-timeline-widget/';
		} else {
			$base_url = esc_url( Redirect::get_url( 'jetpack-support-extra-sidebar-widgets-twitter-timeline-widget' ) );
		}
		return '<a class="widget-access-link" href="' . $base_url . $hash . '" target="_blank"> Need help?</a>';
	}

	/**
	 * Back end widget form.
	 *
	 * @see WP_Widget::form()
	 *
	 * @param array $instance Previously saved values from database.
	 */
	public function form( $instance ) {
		$defaults = array(
			'title'         => esc_html__( 'Follow me on Twitter', 'jetpack' ),
			'width'         => '220',
			'height'        => '200',
			'type'          => 'profile',
			'widget-id'     => '',
			'border-color'  => '#f0f0f1',
			'theme'         => 'light',
			'chrome'        => array(),
			'tweet-limit'   => 1,
			'tweet-display' => 'dynamic',
		);

		$instance = wp_parse_args( (array) $instance, $defaults );

		if ( 'widget-id' === $instance['type'] ) {
			$instance['widget-id'] = '';
		}

		$instance['type'] = 'profile';

		/**
		 * Set the tweet-display option to 'fixed' if height is empty and tweet-limit set
		 * to ensure backwards compatibility with pre-existing widgets.
		 */
		if ( empty( $instance['height'] ) && isset( $instance['tweet-limit'] ) ) {
			$instance['tweet-display'] = 'fixed';
		}
		?>

		<p class="jetpack-twitter-timeline-widget-id-container">
			<label for="<?php echo esc_attr( $this->get_field_id( 'widget-id' ) ); ?>">
				<?php esc_html_e( 'Twitter username:', 'jetpack' ); ?>
				<?php
					echo wp_kses(
						$this->get_docs_link( '#twitter-username' ),
						array(
							'a' => array(
								'href'   => array(),
								'rel'    => array(),
								'target' => array(),
								'class'  => array(),
							),
						)
					);
				?>
			</label>
			<input
				class="widefat"
				id="<?php echo esc_attr( $this->get_field_id( 'widget-id' ) ); ?>"
				name="<?php echo esc_attr( $this->get_field_name( 'widget-id' ) ); ?>"
				type="text"
				value="<?php echo esc_attr( $instance['widget-id'] ); ?>"
			/>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>">
				<?php esc_html_e( 'Title:', 'jetpack' ); ?>
			</label>
			<input
				class="widefat"
				id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"
				name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>"
				type="text"
				value="<?php echo esc_attr( $instance['title'] ); ?>"
			/>
		</p>

		<p>
			<label>
				<strong><?php esc_html_e( 'Number of tweets shown:', 'jetpack' ); ?></strong>
			</label>
			<ul>
				<li>
					<label>
						<input
							id="<?php echo esc_attr( $this->get_field_id( 'tweet-display' ) ); ?>-dynamic"
							name="<?php echo esc_attr( $this->get_field_name( 'tweet-display' ) ); ?>"
							type="radio"
							class="jetpack-twitter-timeline-widget-tweet-display-radio"
							value="dynamic"
							<?php checked( 'dynamic', $instance['tweet-display'] ); ?>
						/>
						<?php esc_html_e( 'Dynamic', 'jetpack' ); ?>
					</label>
				</li>
				<li>
					<label>
						<input
							id="<?php echo esc_attr( $this->get_field_id( 'tweet-display' ) ); ?>-fixed"
							name="<?php echo esc_attr( $this->get_field_name( 'tweet-display' ) ); ?>"
							type="radio"
							class="jetpack-twitter-timeline-widget-tweet-display-radio"
							value="fixed"
							<?php checked( 'fixed', $instance['tweet-display'] ); ?>
						/>
						<?php esc_html_e( 'Fixed', 'jetpack' ); ?>
					</label>
				</li>
			</ul>
		</p>

		<p class="jetpack-twitter-timeline-widget-height-container" <?php echo ( 'fixed' === $instance['tweet-display'] ) ? ' style="display:none;"' : ''; ?>>
			<label for="<?php echo esc_attr( $this->get_field_id( 'height' ) ); ?>">
				<?php esc_html_e( 'Height (in pixels; at least 200):', 'jetpack' ); ?>
			</label>
			<input
				class="widefat"
				id="<?php echo esc_attr( $this->get_field_id( 'height' ) ); ?>"
				name="<?php echo esc_attr( $this->get_field_name( 'height' ) ); ?>"
				type="number" min="200"
				value="<?php echo esc_attr( $instance['height'] ); ?>"
			/>
		</p>

		<p class="jetpack-twitter-timeline-widget-tweet-limit-container" <?php echo ( 'dynamic' === $instance['tweet-display'] ) ? ' style="display:none;"' : ''; ?>>
			<label for="<?php echo esc_attr( $this->get_field_id( 'tweet-limit' ) ); ?>">
				<?php esc_html_e( 'Number of tweets in the timeline (1 to 20):', 'jetpack' ); ?>
			</label>
			<input
				class="widefat"
				id="<?php echo esc_attr( $this->get_field_id( 'tweet-limit' ) ); ?>"
				name="<?php echo esc_attr( $this->get_field_name( 'tweet-limit' ) ); ?>"
				type="number" min="1" max="20"
				value="<?php echo esc_attr( $instance['tweet-limit'] ); ?>"
			/>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'width' ) ); ?>">
				<?php esc_html_e( 'Maximum width (in pixels; 220 to 1200):', 'jetpack' ); ?>
			</label>
			<input
				class="widefat"
				id="<?php echo esc_attr( $this->get_field_id( 'width' ) ); ?>"
				name="<?php echo esc_attr( $this->get_field_name( 'width' ) ); ?>"
				type="number" min="220" max="1200"
				value="<?php echo esc_attr( $instance['width'] ); ?>"
			/>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'chrome-noheader' ) ); ?>">
				<strong><?php esc_html_e( 'Layout options:', 'jetpack' ); ?></strong>
			</label>
		</p>
		<p>
			<input
				type="checkbox"
				<?php checked( false, in_array( 'noheader', $instance['chrome'], true ) ); ?>
				id="<?php echo esc_attr( $this->get_field_id( 'chrome-noheader' ) ); ?>"
				name="<?php echo esc_attr( $this->get_field_name( 'chrome' ) ); ?>[]"
				value="noheader"
			/>
			<label for="<?php echo esc_attr( $this->get_field_id( 'chrome-noheader' ) ); ?>">
				<?php esc_html_e( 'Show header', 'jetpack' ); ?>
			</label>
			<br />
			<input
				type="checkbox"
				<?php checked( false, in_array( 'nofooter', $instance['chrome'], true ) ); ?>
				id="<?php echo esc_attr( $this->get_field_id( 'chrome-nofooter' ) ); ?>"
				name="<?php echo esc_attr( $this->get_field_name( 'chrome' ) ); ?>[]"
				value="nofooter"
			/>
			<label for="<?php echo esc_attr( $this->get_field_id( 'chrome-nofooter' ) ); ?>">
				<?php esc_html_e( 'Show footer', 'jetpack' ); ?>
			</label>
			<br />
			<input
				type="checkbox"
				<?php checked( false, in_array( 'noborders', $instance['chrome'], true ) ); ?>
				id="<?php echo esc_attr( $this->get_field_id( 'chrome-noborders' ) ); ?>"
				name="<?php echo esc_attr( $this->get_field_name( 'chrome' ) ); ?>[]"
				value="noborders"
			/>
			<label for="<?php echo esc_attr( $this->get_field_id( 'chrome-noborders' ) ); ?>">
				<?php esc_html_e( 'Show borders', 'jetpack' ); ?>
			</label>
			<br />
			<input
				type="checkbox"
				<?php checked( false, in_array( 'noscrollbar', $instance['chrome'], true ) ); ?>
				id="<?php echo esc_attr( $this->get_field_id( 'chrome-noscrollbar' ) ); ?>"
				name="<?php echo esc_attr( $this->get_field_name( 'chrome' ) ); ?>[]"
				value="noscrollbar"
				<?php disabled( 'fixed', $instance['tweet-display'] ); ?>
			/>
			<label for="<?php echo esc_attr( $this->get_field_id( 'chrome-noscrollbar' ) ); ?>">
				<?php esc_html_e( 'Show scrollbar', 'jetpack' ); ?>
			</label>
			<br />
			<input
				type="checkbox"
				<?php checked( in_array( 'transparent', $instance['chrome'], true ) ); ?>
				id="<?php echo esc_attr( $this->get_field_id( 'chrome-transparent' ) ); ?>"
				name="<?php echo esc_attr( $this->get_field_name( 'chrome' ) ); ?>[]"
				value="transparent"
			/>
			<label for="<?php echo esc_attr( $this->get_field_id( 'chrome-transparent' ) ); ?>">
				<?php esc_html_e( 'Transparent background', 'jetpack' ); ?>
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'border-color' ) ); ?>">
				<?php esc_html_e( 'Border color (in hex format):', 'jetpack' ); ?>
			</label>
			<input
				class="widefat"
				id="<?php echo esc_attr( $this->get_field_id( 'border-color' ) ); ?>"
				name="<?php echo esc_attr( $this->get_field_name( 'border-color' ) ); ?>"
				type="text"
				value="<?php echo esc_attr( $instance['border-color'] ); ?>"
			/>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'theme' ) ); ?>">
				<?php esc_html_e( 'Color scheme:', 'jetpack' ); ?>
			</label>
			<select
				name="<?php echo esc_attr( $this->get_field_name( 'theme' ) ); ?>"
				id="<?php echo esc_attr( $this->get_field_id( 'theme' ) ); ?>"
				class="widefat"
			>
				<option value="light"<?php selected( $instance['theme'], 'light' ); ?>>
					<?php esc_html_e( 'Light', 'jetpack' ); ?>
				</option>
				<option value="dark"<?php selected( $instance['theme'], 'dark' ); ?>>
					<?php esc_html_e( 'Dark', 'jetpack' ); ?>
				</option>
			</select>
		</p>
		<?php
	}
}
