<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * For back-compat, the final widget class must be named
 * Jetpack_Display_Posts_Widget.
 *
 * For convenience, it's nice to have a widget class constructor with no
 * arguments. Otherwise, we have to register the widget with an instance
 * instead of a class name. This makes unregistering annoying.
 *
 * Both WordPress.com and Jetpack implement the final widget class by
 * extending this __Base class and adding data fetching and storage.
 *
 * This would be a bit cleaner with dependency injection, but we already
 * use mocking to test, so it's not a big win.
 *
 * That this widget is currently implemented as these two classes
 * is an implementation detail and should not be depended on :)
 *
 * phpcs:disable PEAR.NamingConventions.ValidClassName.Invalid
 */
abstract class Jetpack_Display_Posts_Widget__Base extends WP_Widget {
	// phpcs:enable PEAR.NamingConventions.ValidClassName.Invalid

	/**
	 * Remote service API URL prefix.
	 *
	 * @var string
	 */
	public $service_url = 'https://public-api.wordpress.com/rest/v1.1/';

	/**
	 * Jetpack_Display_Posts_Widget__Base constructor.
	 */
	public function __construct() {
		parent::__construct(
		// Internal id.
			'jetpack_display_posts_widget',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', __( 'Display WordPress Posts', 'jetpack' ) ),
			array(
				'description'                 => __( 'Displays a list of recent posts from another WordPress.com or Jetpack-enabled blog.', 'jetpack' ),
				'customize_selective_refresh' => true,
			)
		);

		if ( is_customize_preview() ) {
			add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		}
	}

	/**
	 * Enqueue CSS and JavaScript.
	 *
	 * @since 4.0.0
	 */
	public function enqueue_scripts() {
		wp_enqueue_style(
			'jetpack_display_posts_widget',
			plugins_url( 'style.css', __FILE__ ),
			array(),
			JETPACK__VERSION
		);
	}

	// DATA STORE: Must implement.

	/**
	 * Gets blog data from the cache.
	 *
	 * @param string $site Site.
	 *
	 * @return array|WP_Error
	 */
	abstract public function get_blog_data( $site );

	/**
	 * Update a widget instance.
	 *
	 * @param string $site The site to fetch the latest data for.
	 *
	 * @return array - the new data
	 */
	abstract public function update_instance( $site );

	// WIDGET API.

	/**
	 * Set up the widget display on the front end.
	 *
	 * @param array $args Widget args.
	 * @param array $instance Widget instance.
	 */
	public function widget( $args, $instance ) {
		/** This action is documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'display_posts' );

		// Enqueue front end assets.
		$this->enqueue_scripts();

		$content = $args['before_widget'];

		if ( empty( $instance['url'] ) ) {
			if ( current_user_can( 'manage_options' ) ) {
				$content .= '<p>';
				/* Translators: the "Blog URL" field mentioned is the input field labeled as such in the widget form. */
				$content .= esc_html__( 'The Blog URL is not properly setup in the widget.', 'jetpack' );
				$content .= '</p>';
			}
			$content .= $args['after_widget'];

			echo $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			return;
		}

		$data = $this->get_blog_data( $instance['url'] );
		// Check for errors.
		if ( is_wp_error( $data ) || empty( $data['site_info']['data'] ) ) {
			$content .= '<p>' . __( 'Cannot load blog information at this time.', 'jetpack' ) . '</p>';
			$content .= $args['after_widget'];

			echo $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			return;
		}

		$site_info = $data['site_info']['data'];

		if ( ! empty( $instance['title'] ) ) {
			/** This filter is documented in core/src/wp-includes/default-widgets.php */
			$instance['title'] = apply_filters( 'widget_title', $instance['title'] );
			$content          .= $args['before_title'] . $instance['title'] . ': ' . $site_info->name . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		} else {
			$content .= $args['before_title'] . esc_html( $site_info->name ) . $args['after_title'];
		}

		$content .= '<div class="jetpack-display-remote-posts">';

		if ( is_wp_error( $data['posts']['data'] ) || empty( $data['posts']['data'] ) ) {
			$content .= '<p>' . __( 'Cannot load blog posts at this time.', 'jetpack' ) . '</p>';
			$content .= '</div><!-- .jetpack-display-remote-posts -->';
			$content .= $args['after_widget'];

			echo $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			return;
		}

		$posts_list = $data['posts']['data'];

		/**
		 * Show only as much posts as we need. If we have less than configured amount,
		 * we must show only that much posts.
		 */
		$number_of_posts = min( $instance['number_of_posts'], count( $posts_list ) );

		for ( $i = 0; $i < $number_of_posts; $i++ ) {
			$single_post = $posts_list[ $i ];
			$post_title  = ( $single_post['title'] ) ? $single_post['title'] : '( No Title )';

			$target = '';
			if ( isset( $instance['open_in_new_window'] ) && true === $instance['open_in_new_window'] ) {
				$target = ' target="_blank" rel="noopener"';
			}
			$content .= '<h4><a href="' . esc_url( $single_post['url'] ) . '"' . $target . '>' . esc_html( $post_title ) . '</a></h4>' . "\n";
			if ( ( true === $instance['featured_image'] ) && ( ! empty( $single_post['featured_image'] ) ) ) {
				$featured_image = $single_post['featured_image'];
				/**
				 * Allows setting up custom Photon parameters to manipulate the image output in the Display Posts widget.
				 *
				 * @see    https://developer.wordpress.com/docs/photon/
				 *
				 * @module widgets
				 *
				 * @since  3.6.0
				 *
				 * @param array $args Array of Photon Parameters.
				 */
				$image_params = apply_filters( 'jetpack_display_posts_widget_image_params', array() );
				$content     .= '<a title="' . esc_attr( $post_title ) . '" href="' . esc_url( $single_post['url'] ) . '"' . $target . '><img src="' . jetpack_photon_url( $featured_image, $image_params ) . '" alt="' . esc_attr( $post_title ) . '"/></a>';
			}

			if ( true === $instance['show_excerpts'] ) {
				$content .= $single_post['excerpt'];
			}
		}

		$content .= '</div><!-- .jetpack-display-remote-posts -->';
		$content .= $args['after_widget'];

		/**
		 * Filter the WordPress Posts widget content.
		 *
		 * @module widgets
		 *
		 * @since 4.7.0
		 *
		 * @param string $content Widget content.
		 */
		echo apply_filters( 'jetpack_display_posts_widget_content', $content ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * Display the widget administration form.
	 *
	 * @param array $instance Widget instance configuration.
	 *
	 * @return string|void
	 */
	public function form( $instance ) {

		/**
		 * Initialize widget configuration variables.
		 */
		$title              = ( isset( $instance['title'] ) ) ? $instance['title'] : __( 'Recent Posts', 'jetpack' );
		$url                = ( isset( $instance['url'] ) ) ? $instance['url'] : '';
		$number_of_posts    = ( isset( $instance['number_of_posts'] ) ) ? $instance['number_of_posts'] : 5;
		$open_in_new_window = ( isset( $instance['open_in_new_window'] ) ) ? $instance['open_in_new_window'] : false;
		$featured_image     = ( isset( $instance['featured_image'] ) ) ? $instance['featured_image'] : false;
		$show_excerpts      = ( isset( $instance['show_excerpts'] ) ) ? $instance['show_excerpts'] : false;

		/**
		 * Check if the widget instance has errors available.
		 *
		 * Only do so if a URL is set.
		 */
		$update_errors = array();

		if ( ! empty( $url ) ) {
			$data          = $this->get_blog_data( $url );
			$update_errors = $this->extract_errors_from_blog_data( $data );
		}

		?>
		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"><?php esc_html_e( 'Title:', 'jetpack' ); ?></label>
			<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" type="text" value="<?php echo esc_attr( $title ); ?>" />
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'url' ) ); ?>"><?php esc_html_e( 'Blog URL:', 'jetpack' ); ?></label>
			<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'url' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'url' ) ); ?>" type="text" value="<?php echo esc_attr( $url ); ?>" />
			<i>
				<?php esc_html_e( 'Enter a WordPress.com or Jetpack WordPress site URL.', 'jetpack' ); ?>
			</i>
			<?php
			/**
			 * Show an error if the URL field was left empty.
			 *
			 * The error is shown only when the widget was already saved.
			 */
			if ( empty( $url ) && ! preg_match( '/__i__|%i%/', $this->id ) ) {
				?>
				<br />
				<i class="error-message"><?php esc_html_e( 'You must specify a valid blog URL!', 'jetpack' ); ?></i>
				<?php
			}
			?>
		</p>
		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'number_of_posts' ) ); ?>"><?php esc_html_e( 'Number of Posts to Display:', 'jetpack' ); ?></label>
			<select name="<?php echo esc_attr( $this->get_field_name( 'number_of_posts' ) ); ?>">
				<?php
				for ( $i = 1; $i <= 10; $i++ ) {
					echo '<option value="' . esc_attr( $i ) . '" ' . selected( $number_of_posts, $i ) . '>' . esc_html( $i ) . '</option>';
				}
				?>
			</select>
		</p>
		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'open_in_new_window' ) ); ?>"><?php esc_html_e( 'Open links in new window/tab:', 'jetpack' ); ?></label>
			<input type="checkbox" name="<?php echo esc_attr( $this->get_field_name( 'open_in_new_window' ) ); ?>" <?php checked( $open_in_new_window, 1 ); ?> />
		</p>
		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'featured_image' ) ); ?>"><?php esc_html_e( 'Show Featured Image:', 'jetpack' ); ?></label>
			<input type="checkbox" name="<?php echo esc_attr( $this->get_field_name( 'featured_image' ) ); ?>" <?php checked( $featured_image, 1 ); ?> />
		</p>
		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'show_excerpts' ) ); ?>"><?php esc_html_e( 'Show Excerpts:', 'jetpack' ); ?></label>
			<input type="checkbox" name="<?php echo esc_attr( $this->get_field_name( 'show_excerpts' ) ); ?>" <?php checked( $show_excerpts, 1 ); ?> />
		</p>

		<?php

		/**
		 * Show error messages.
		 */
		if ( ! empty( $update_errors['message'] ) ) {

			/**
			 * Prepare the error messages.
			 */

			$where_message = '';
			switch ( $update_errors['where'] ) {
				case 'posts':
					$where_message .= __( 'An error occurred while downloading blog posts list', 'jetpack' );
					break;

				/**
				 * If something else, beside `posts` and `site_info` broke,
				 * don't handle it and default to blog `information`,
				 * as it is generic enough.
				 */
				case 'site_info':
				default:
					$where_message .= __( 'An error occurred while downloading blog information', 'jetpack' );
					break;
			}

			?>
			<p class="error-message">
				<?php echo esc_html( $where_message ); ?>:
				<br />
				<i>
					<?php echo esc_html( $update_errors['message'] ); ?>
					<?php
					/**
					 * If there is any debug - show it here.
					 */
					if ( ! empty( $update_errors['debug'] ) ) {
						?>
						<br />
						<br />
						<?php esc_html_e( 'Detailed information', 'jetpack' ); ?>:
						<br />
						<?php echo esc_html( $update_errors['debug'] ); ?>
						<?php
					}
					?>
				</i>
			</p>

			<?php
		}
	}

	/**
	 * Widget update function.
	 *
	 * @param array $new_instance New instance widget settings.
	 * @param array $old_instance Old instance widget settings.
	 */
	public function update( $new_instance, $old_instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable

		$instance          = array();
		$instance['title'] = ( ! empty( $new_instance['title'] ) ) ? wp_strip_all_tags( $new_instance['title'] ) : '';
		$instance['url']   = ( ! empty( $new_instance['url'] ) ) ? wp_strip_all_tags( trim( $new_instance['url'] ) ) : '';
		$instance['url']   = preg_replace( '!^https?://!is', '', $instance['url'] );
		$instance['url']   = untrailingslashit( $instance['url'] );

		/**
		 * Check if the URL should be with or without the www prefix before saving.
		 */
		if ( ! empty( $instance['url'] ) ) {
			$blog_data = $this->fetch_blog_data( $instance['url'], array(), true );

			if ( is_wp_error( $blog_data['site_info']['error'] ) && 'www.' === substr( $instance['url'], 0, 4 ) ) {
				$blog_data = $this->fetch_blog_data( substr( $instance['url'], 4 ), array(), true );

				if ( ! is_wp_error( $blog_data['site_info']['error'] ) ) {
					$instance['url'] = substr( $instance['url'], 4 );
				}
			}
		}

		$instance['number_of_posts']    = ( ! empty( $new_instance['number_of_posts'] ) ) ? (int) $new_instance['number_of_posts'] : '';
		$instance['open_in_new_window'] = ( ! empty( $new_instance['open_in_new_window'] ) ) ? true : '';
		$instance['featured_image']     = ( ! empty( $new_instance['featured_image'] ) ) ? true : '';
		$instance['show_excerpts']      = ( ! empty( $new_instance['show_excerpts'] ) ) ? true : '';

		/**
		 * If there is no cache entry for the specified URL, run a forced update.
		 *
		 * @see get_blog_data Returns WP_Error if the cache is empty, which is what is needed here.
		 */
		$cached_data = $this->get_blog_data( $instance['url'] );

		if ( is_wp_error( $cached_data ) ) {
			$this->update_instance( $instance['url'] );
		}

		return $instance;
	}

	// DATA PROCESSING.

	/**
	 * Expiring transients have a name length maximum of 45 characters,
	 * so this function returns an abbreviated MD5 hash to use instead of
	 * the full URI.
	 *
	 * @param string $site Site to get the hash for.
	 *
	 * @return string
	 */
	public function get_site_hash( $site ) {
		return substr( md5( $site ), 0, 21 );
	}

	/**
	 * Fetch a remote service endpoint and parse it.
	 *
	 * Timeout is set to 15 seconds right now, because sometimes the WordPress API
	 * takes more than 5 seconds to fully respond.
	 *
	 * Caching is used here so we can avoid re-downloading the same endpoint
	 * in a single request.
	 *
	 * @param string $endpoint Parametrized endpoint to call.
	 *
	 * @param int    $timeout  How much time to wait for the API to respond before failing.
	 *
	 * @return array|WP_Error
	 */
	public function fetch_service_endpoint( $endpoint, $timeout = 15 ) {

		/**
		 * Holds endpoint request cache.
		 */
		static $cache = array();

		if ( ! isset( $cache[ $endpoint ] ) ) {
			$raw_data           = $this->wp_wp_remote_get( $this->service_url . ltrim( $endpoint, '/' ), array( 'timeout' => $timeout ) );
			$cache[ $endpoint ] = $this->parse_service_response( $raw_data );
		}

		return $cache[ $endpoint ];
	}

	/**
	 * Parse data from service response.
	 * Do basic error handling for general service and data errors
	 *
	 * @param array $service_response Response from the service.
	 *
	 * @return array|WP_Error
	 */
	public function parse_service_response( $service_response ) {
		/**
		 * If there is an error, we add the error message to the parsed response
		 */
		if ( is_wp_error( $service_response ) ) {
			return new WP_Error(
				'general_error',
				__( 'An error occurred fetching the remote data.', 'jetpack' ),
				$service_response->get_error_messages()
			);
		}

		/**
		 * Validate HTTP response code.
		 */
		if ( 200 !== wp_remote_retrieve_response_code( $service_response ) ) {
			return new WP_Error(
				'http_error',
				__( 'An error occurred fetching the remote data.', 'jetpack' ),
				wp_remote_retrieve_response_message( $service_response )
			);
		}

		/**
		 * Extract service response body from the request.
		 */

		$service_response_body = wp_remote_retrieve_body( $service_response );

		/**
		 * No body has been set in the response. This should be pretty bad.
		 */
		if ( ! $service_response_body ) {
			return new WP_Error(
				'no_body',
				__( 'Invalid remote response.', 'jetpack' ),
				'No body in response.'
			);
		}

		/**
		 * Parse the JSON response from the API. Convert to associative array.
		 */
		$parsed_data = json_decode( $service_response_body );

		/**
		 * If there is a problem with parsing the posts return an empty array.
		 */
		if ( $parsed_data === null ) {
			return new WP_Error(
				'no_body',
				__( 'Invalid remote response.', 'jetpack' ),
				'Invalid JSON from remote.'
			);
		}

		/**
		 * Check for errors in the parsed body.
		 */
		if ( isset( $parsed_data->error ) ) {
			return new WP_Error(
				'remote_error',
				__( 'It looks like the WordPress site URL is incorrectly configured. Please check it in your widget settings.', 'jetpack' ),
				$parsed_data->error
			);
		}

		/**
		 * No errors found, return parsed data.
		 */
		return $parsed_data;
	}

	/**
	 * Fetch site information from the WordPress public API
	 *
	 * @param string $site URL of the site to fetch the information for.
	 *
	 * @return array|WP_Error
	 */
	public function fetch_site_info( $site ) {

		$response = $this->fetch_service_endpoint( sprintf( '/sites/%s', rawurlencode( $site ) ) );

		return $response;
	}

	/**
	 * Parse external API response from the site info call and handle errors if they occur.
	 *
	 * @param array|WP_Error $service_response The raw response to be parsed.
	 *
	 * @return array|WP_Error
	 */
	public function parse_site_info_response( $service_response ) {

		/**
		 * If the service returned an error, we pass it on.
		 */
		if ( is_wp_error( $service_response ) ) {
			return $service_response;
		}

		/**
		 * Check if the service returned proper site information.
		 */
		if ( ! isset( $service_response->ID ) ) {
			return new WP_Error(
				'no_site_info',
				__( 'Invalid site information returned from remote.', 'jetpack' ),
				'No site ID present in the response.'
			);
		}

		return $service_response;
	}

	/**
	 * Fetch list of posts from the WordPress public API.
	 *
	 * @param int $site_id The site to fetch the posts for.
	 *
	 * @return array|WP_Error
	 */
	public function fetch_posts_for_site( $site_id ) {

		$response = $this->fetch_service_endpoint(
			sprintf(
				'/sites/%1$d/posts/%2$s',
				$site_id,
				/**
				 * Filters the parameters used to fetch for posts in the Display Posts Widget.
				 *
				 * @see    https://developer.wordpress.com/docs/api/1.1/get/sites/%24site/posts/
				 *
				 * @module widgets
				 *
				 * @since  3.6.0
				 *
				 * @param string $args Extra parameters to filter posts returned from the WordPress.com REST API.
				 */
				apply_filters( 'jetpack_display_posts_widget_posts_params', '?fields=id,title,excerpt,URL,featured_image' )
			)
		);

		return $response;
	}

	/**
	 * Parse external API response from the posts list request and handle errors if any occur.
	 *
	 * @param object|WP_Error $service_response The raw response to be parsed.
	 *
	 * @return array|WP_Error
	 */
	public function parse_posts_response( $service_response ) {

		/**
		 * If the service returned an error, we pass it on.
		 */
		if ( is_wp_error( $service_response ) ) {
			return $service_response;
		}

		/**
		 * Check if the service returned proper posts array.
		 */
		if ( ! isset( $service_response->posts ) || ! is_array( $service_response->posts ) ) {
			return new WP_Error(
				'no_posts',
				__( 'No posts data returned by remote.', 'jetpack' ),
				'No posts information set in the returned data.'
			);
		}

		/**
		 * Format the posts to preserve storage space.
		 */

		return $this->format_posts_for_storage( $service_response );
	}

	/**
	 * Format the posts for better storage. Drop all the data that is not used.
	 *
	 * @param object $parsed_data Array of posts returned by the APIs.
	 *
	 * @return array Formatted posts or an empty array if no posts were found.
	 */
	public function format_posts_for_storage( $parsed_data ) {

		$formatted_posts = array();

		/**
		 * Only go through the posts list if we have valid posts array.
		 */
		if ( isset( $parsed_data->posts ) && is_array( $parsed_data->posts ) ) {

			/**
			 * Loop through all the posts and format them appropriately.
			 */
			foreach ( $parsed_data->posts as $single_post ) {

				$prepared_post = array(
					'title'          => $single_post->title ? $single_post->title : '',
					'excerpt'        => $single_post->excerpt ? $single_post->excerpt : '',
					'featured_image' => $single_post->featured_image ? $single_post->featured_image : '',
					'url'            => $single_post->URL, // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				);

				/**
				 * Append the formatted post to the results.
				 */
				$formatted_posts[] = $prepared_post;
			}
		}

		return $formatted_posts;
	}

	/**
	 * Fetch site information and posts list for a site.
	 *
	 * @param string $site           Site to fetch the data for.
	 * @param array  $original_data  Optional original data to updated.
	 *
	 * @param bool   $site_data_only Fetch only site information, skip posts list.
	 *
	 * @return array Updated or new data.
	 */
	public function fetch_blog_data( $site, $original_data = array(), $site_data_only = false ) {

		/**
		 * If no optional data is supplied, initialize a new structure
		 */
		if ( ! empty( $original_data ) ) {
			$widget_data = $original_data;
		} else {
			$widget_data = array(
				'site_info' => array(
					'last_check'  => null,
					'last_update' => null,
					'error'       => null,
					'data'        => array(),
				),
				'posts'     => array(
					'last_check'  => null,
					'last_update' => null,
					'error'       => null,
					'data'        => array(),
				),
			);
		}

		/**
		 * Update check time and fetch site information.
		 */
		$widget_data['site_info']['last_check'] = time();

		$site_info_raw_data    = $this->fetch_site_info( $site );
		$site_info_parsed_data = $this->parse_site_info_response( $site_info_raw_data );

		/**
		 * If there is an error with the fetched site info, save the error and update the checked time.
		 */
		if ( is_wp_error( $site_info_parsed_data ) ) {
			$widget_data['site_info']['error'] = $site_info_parsed_data;

			return $widget_data;
		} else {
			/**
			 * If data is fetched successfully, update the data and set the proper time.
			 *
			 * Data is only updated if we have valid results. This is done this way so we can show
			 * something if external service is down.
			 */
			$widget_data['site_info']['last_update'] = time();
			$widget_data['site_info']['data']        = $site_info_parsed_data;
			$widget_data['site_info']['error']       = null;
		}

		/**
		 * If only site data is needed, return it here, don't fetch posts data.
		 */
		if ( true === $site_data_only ) {
			return $widget_data;
		}

		/**
		 * Update check time and fetch posts list.
		 */
		$widget_data['posts']['last_check'] = time();

		$site_posts_raw_data    = $this->fetch_posts_for_site( $site_info_parsed_data->ID );
		$site_posts_parsed_data = $this->parse_posts_response( $site_posts_raw_data );

		/**
		 * If there is an error with the fetched posts, save the error and update the checked time.
		 */
		if ( is_wp_error( $site_posts_parsed_data ) ) {
			$widget_data['posts']['error'] = $site_posts_parsed_data;

			return $widget_data;
		} else {
			/**
			 * If data is fetched successfully, update the data and set the proper time.
			 *
			 * Data is only updated if we have valid results. This is done this way so we can show
			 * something if external service is down.
			 */
			$widget_data['posts']['last_update'] = time();
			$widget_data['posts']['data']        = $site_posts_parsed_data;
			$widget_data['posts']['error']       = null;
		}

		return $widget_data;
	}

	/**
	 * Scan and extract first error from blog data array.
	 *
	 * @param array|WP_Error $blog_data Blog data to scan for errors.
	 *
	 * @return string First error message found
	 */
	public function extract_errors_from_blog_data( $blog_data ) {

		$errors = array(
			'message' => '',
			'debug'   => '',
			'where'   => '',
		);

		/**
		 * When the cache result is an error. Usually when the cache is empty.
		 * This is not an error case for now.
		 */
		if ( is_wp_error( $blog_data ) ) {
			return $errors;
		}

		/**
		 * Loop through `site_info` and `posts` keys of $blog_data.
		 */
		foreach ( array( 'site_info', 'posts' ) as $info_key ) {

			/**
			 * Contains information on which stage the error ocurred.
			 */
			$errors['where'] = $info_key;

			/**
			 * If an error is set, we want to check it for usable messages.
			 */
			if ( isset( $blog_data[ $info_key ]['error'] ) && ! empty( $blog_data[ $info_key ]['error'] ) ) {

				/**
				 * Extract error message from the error, if possible.
				 */
				if ( is_wp_error( $blog_data[ $info_key ]['error'] ) ) {
					/**
					 * In the case of WP_Error we want to have the error message
					 * and the debug information available.
					 */
					$error_messages    = $blog_data[ $info_key ]['error']->get_error_messages();
					$errors['message'] = reset( $error_messages );

					$extra_data = $blog_data[ $info_key ]['error']->get_error_data();
					if ( is_array( $extra_data ) ) {
						$errors['debug'] = implode( '; ', $extra_data );
					} else {
						$errors['debug'] = $extra_data;
					}

					break;
				} elseif ( is_array( $blog_data[ $info_key ]['error'] ) ) {
					/**
					 * In this case we don't have debug information, because
					 * we have no way to know the format. The widget works with
					 * WP_Error objects only.
					 */
					$errors['message'] = reset( $blog_data[ $info_key ]['error'] );
					break;
				}

				/**
				 * We do nothing if no usable error is found.
				 */
			}
		}

		return $errors;
	}

	/**
	 * This is just to make method mocks in the unit tests easier.
	 *
	 * @param string $url  The URL to fetch.
	 * @param array  $args Optional. Request arguments.
	 *
	 * @return array|WP_Error
	 *
	 * @codeCoverageIgnore
	 */
	public function wp_wp_remote_get( $url, $args = array() ) {
		return wp_remote_get( $url, $args );
	}
}
