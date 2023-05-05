<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Disable direct access/execution to/of the widget code.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Jetpack_Flickr_Widget' ) ) {
	/**
	 * Flickr Widget
	 *
	 * Display your recent Flickr photos.
	 */
	class Jetpack_Flickr_Widget extends WP_Widget {
		/**
		 * Constructor.
		 */
		public function __construct() {
			parent::__construct(
				'flickr',
				/** This filter is documented in modules/widgets/facebook-likebox.php */
				apply_filters( 'jetpack_widget_name', esc_html__( 'Flickr', 'jetpack' ) ),
				array(
					'description'                 => esc_html__( 'Display your recent Flickr photos.', 'jetpack' ),
					'customize_selective_refresh' => true,
				),
				array()
			);

			if ( is_active_widget( false, false, $this->id_base ) || is_customize_preview() ) {
				add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_style' ) );
			}
		}

		/**
		 * Enqueue style.
		 */
		public function enqueue_style() {
			wp_enqueue_style( 'flickr-widget-style', plugins_url( 'flickr/style.css', __FILE__ ), array(), '20170405' );
		}

		/**
		 * Return an associative array of default values.
		 *
		 * These values are used in new widgets.
		 *
		 * @return array Default values for the widget options.
		 */
		public function defaults() {
			return array(
				'title'             => esc_html__( 'Flickr Photos', 'jetpack' ),
				'items'             => 4,
				'target'            => false,
				'flickr_image_size' => 'thumbnail',
				'flickr_rss_url'    => '',
			);
		}

		/**
		 * Front-end display of the widget.
		 *
		 * @param array $args     Widget arguments.
		 * @param array $instance Saved values from database.
		 */
		public function widget( $args, $instance ) {
			$instance = wp_parse_args( $instance, $this->defaults() );

			if ( ! empty( $instance['flickr_rss_url'] ) ) {
				/*
				 * Parse the URL, and rebuild a URL that's sure to display images.
				 * Some Flickr Feeds do not display images by default.
				 */
				$flickr_parameters = wp_parse_url( htmlspecialchars_decode( $instance['flickr_rss_url'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 ) );

				// Is it a Flickr Feed.
				if (
					! empty( $flickr_parameters['host'] )
					&& ! empty( $flickr_parameters['query'] )
					&& false !== strpos( $flickr_parameters['host'], 'flickr' )
				) {
					parse_str( $flickr_parameters['query'], $vars );

					// Do we have an ID in the feed? Let's continue.
					if ( isset( $vars['id'] ) ) {

						// Flickr Feeds can be used for groups or for individuals.
						if (
							! empty( $flickr_parameters['path'] )
							&& false !== strpos( $flickr_parameters['path'], 'groups' )
						) {
							$feed_url = 'https://api.flickr.com/services/feeds/groups_pool.gne';
						} else {
							$feed_url = 'https://api.flickr.com/services/feeds/photos_public.gne';
						}

						// Build our new RSS feed.
						$rss_url = sprintf(
							'%1$s?id=%2$s&format=rss_200_enc',
							esc_url( $feed_url ),
							esc_attr( $vars['id'] )
						);
					}
				}
			}

			// Still no RSS feed URL? Get a default feed from Flickr to grab interesting photos.
			if ( empty( $rss_url ) ) {
				$rss_url = 'https://api.flickr.com/services/feeds/photos_interesting.gne?format=rss_200';
			}

			$rss = fetch_feed( $rss_url );

			$photos = '';
			if ( ! is_wp_error( $rss ) ) {
				foreach ( $rss->get_items( 0, $instance['items'] ) as $photo ) {
					switch ( $instance['flickr_image_size'] ) {
						case 'thumbnail':
							$src = $photo->get_enclosure()->get_thumbnail();
							break;
						case 'small':
							$src = preg_match( '/src="(.*?)"/i', $photo->get_description(), $p );
							$src = $p[1];
							break;
						case 'large':
							$src = $photo->get_enclosure()->get_link();
							break;
					}

					$photos .= '<a href="' . esc_url( $photo->get_permalink(), array( 'http', 'https' ) ) . '" ';
					if ( $instance['target'] ) {
						$photos .= 'target="_blank" rel="noopener noreferrer" ';
					}
					$photos .= '><img src="' . esc_url( $src, array( 'http', 'https' ) ) . '" ';
					$photos .= 'alt="' . esc_attr( $photo->get_title() ) . '" ';
					$photos .= 'title="' . esc_attr( $photo->get_title() ) . '" ';
					$photos .= ' /></a>';
				}
				if ( ! empty( $photos ) && class_exists( 'Jetpack_Photon' ) && Jetpack::is_module_active( 'photon' ) ) {
					$photos = Jetpack_Photon::filter_the_content( $photos );
				}

				$flickr_home = $rss->get_link(); // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable -- Used in flickr/widget.php template file.
			}

			echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			if ( empty( $photos ) ) {
				if ( current_user_can( 'edit_theme_options' ) ) {
					printf(
						'<p>%1$s<br />%2$s</p>',
						esc_html__( 'There are no photos to display. Make sure your Flickr feed URL is correct, and that your pictures are publicly accessible.', 'jetpack' ),
						esc_html__( '(Only admins can see this message)', 'jetpack' )
					);
				}
			} else {
				echo $args['before_title'] . $instance['title'] . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				require __DIR__ . '/flickr/widget.php';
			}
			echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			/** This action is already documented in modules/widgets/gravatar-profile.php */
			do_action( 'jetpack_stats_extra', 'widget_view', 'flickr' );
		}

		/**
		 * Back-end widget form.
		 *
		 * @param array $instance Previously saved values from database.
		 */
		public function form( $instance ) {
			$instance = wp_parse_args( $instance, $this->defaults() );
			require __DIR__ . '/flickr/form.php';
		}

		/**
		 * Sanitize widget form values as they are saved.
		 *
		 * @param  array $new_instance Values just sent to be saved.
		 * @param  array $old_instance Previously saved values from database.
		 * @return array Updated safe values to be saved.
		 */
		public function update( $new_instance, $old_instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
			$instance = array();

			if ( isset( $new_instance['title'] ) ) {
				$instance['title'] = wp_kses( $new_instance['title'], array() );
			}

			if ( isset( $new_instance['items'] ) ) {
				$instance['items'] = (int) $new_instance['items'];
			}

			if ( isset( $new_instance['target'] ) ) {
				$instance['target'] = (bool) $new_instance['target'];
			}

			if (
				isset( $new_instance['flickr_image_size'] ) &&
				in_array( $new_instance['flickr_image_size'], array( 'thumbnail', 'small', 'large' ), true )
			) {
				$instance['flickr_image_size'] = $new_instance['flickr_image_size'];
			} else {
				$instance['flickr_image_size'] = 'thumbnail';
			}

			if ( isset( $new_instance['flickr_rss_url'] ) ) {
				$instance['flickr_rss_url'] = esc_url( $new_instance['flickr_rss_url'], array( 'http', 'https' ) );

				if ( strlen( $instance['flickr_rss_url'] ) < 10 ) {
					$instance['flickr_rss_url'] = '';
				}
			}

			return $instance;
		}
	}

	/**
	 * Register Jetpack_Flickr_Widget widget.
	 */
	function jetpack_register_flickr_widget() {
		register_widget( 'Jetpack_Flickr_Widget' );
	}
	add_action( 'widgets_init', 'jetpack_register_flickr_widget' );
}
