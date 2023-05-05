<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Disable direct access/execution to/of the widget code.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Widget to display blog authors with avatars and recent posts.
 *
 * Configurable parameters include:
 * 1. Whether to display authors who haven't written any posts
 * 2. The number of posts to be displayed per author (defaults to 0)
 * 3. Avatar size
 *
 * @since 4.5.0
 */
class Jetpack_Widget_Authors extends WP_Widget {
	/**
	 * Jetpack_Widget_Authors contructor.
	 */
	public function __construct() {
		parent::__construct(
			'authors',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', __( 'Authors', 'jetpack' ) ),
			array(
				'classname'                   => 'widget_authors',
				'description'                 => __( 'Display blogs authors with avatars and recent posts.', 'jetpack' ),
				'customize_selective_refresh' => true,
			)
		);

		if ( is_active_widget( false, false, $this->id_base ) || is_active_widget( false, false, 'monster' ) || is_customize_preview() ) {
			add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_style' ) );
		}

		add_action( 'publish_post', array( __CLASS__, 'flush_cache' ) );
		add_action( 'deleted_post', array( __CLASS__, 'flush_cache' ) );
		add_action( 'switch_theme', array( __CLASS__, 'flush_cache' ) );
	}

	/**
	 * Enqueue stylesheet to adapt the widget to various themes.
	 *
	 * @since 4.5.0
	 */
	public function enqueue_style() {
		wp_register_style( 'jetpack-authors-widget', plugins_url( 'authors/style.css', __FILE__ ), array(), '20161228' );
		wp_enqueue_style( 'jetpack-authors-widget' );
	}

	/**
	 * Flush Authors widget cached data.
	 */
	public static function flush_cache() {
		wp_cache_delete( 'widget_authors', 'widget' );
		wp_cache_delete( 'widget_authors_ssl', 'widget' );
	}

	/**
	 * Echoes the widget content.
	 *
	 * @param array $args Display arguments.
	 * @param array $instance Widget settings for the instance.
	 */
	public function widget( $args, $instance ) {
		$cache_bucket = is_ssl() ? 'widget_authors_ssl' : 'widget_authors';

		if ( '%BEG_OF_TITLE%' !== $args['before_title'] ) {
			$output = wp_cache_get( $cache_bucket, 'widget' );
			if ( $output ) {
				echo $output; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Cached widget display.
				return;
			}

			ob_start();
		}

		$instance           = wp_parse_args(
			$instance,
			array(
				'title'       => __( 'Authors', 'jetpack' ),
				'all'         => false,
				'number'      => 5,
				'avatar_size' => 48,
			)
		);
		$instance['number'] = min( 10, max( 0, (int) $instance['number'] ) );

		// We need to query at least one post to determine whether an author has written any posts or not.
		$query_number = max( $instance['number'], 1 );

		/**
		 * Filter authors from the Widget Authors widget.
		 *
		 * @module widgets
		 *
		 * @deprecated 7.7.0 Use jetpack_widget_authors_params instead.
		 *
		 * @since 4.5.0
		 *
		 * @param array $default_excluded_authors Array of user ID's that will be excluded
		 */
		$excluded_authors = apply_filters( 'jetpack_widget_authors_exclude', array() );

		/**
		 * Filter the parameters of `get_users` call in the Widget Authors widget.
		 *
		 * See the following for `get_users` default arguments:
		 * https://codex.wordpress.org/Function_Reference/get_users
		 *
		 * @module widgets
		 *
		 * @since 7.7.0
		 *
		 * @param array $get_author_params Array of params used in `get_user`
		 */
		$get_author_params = apply_filters(
			'jetpack_widget_authors_params',
			array(
				'capability' => array( 'edit_posts' ),
				'exclude'    => (array) $excluded_authors,
			)
		);

		$authors = get_users( $get_author_params );

		echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		/** This filter is documented in core/src/wp-includes/default-widgets.php */
		$title = apply_filters( 'widget_title', $instance['title'] );
		echo $args['before_title'] . $title . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<ul>';

		$default_post_type = 'post';
		/**
		 * Filter types of posts that will be counted in the widget
		 *
		 * @module widgets
		 *
		 * @since 4.5.0
		 *
		 * @param string|array $default_post_type type(s) of posts to count for the widget.
		 */
		$post_types = apply_filters( 'jetpack_widget_authors_post_types', $default_post_type );

		foreach ( $authors as $author ) {
			$r = new WP_Query(
				array(
					'author'         => $author->ID,
					'posts_per_page' => $query_number,
					'post_type'      => $post_types,
					'post_status'    => 'publish',
					'no_found_rows'  => true,
					'has_password'   => false,
				)
			);

			if ( ! $r->have_posts() && ! $instance['all'] ) {
				continue;
			}

			echo '<li>';

			// Display avatar and author name.
			if ( $r->have_posts() ) {
				echo '<a href="' . esc_url( get_author_posts_url( $author->ID ) ) . '">';

				if ( $instance['avatar_size'] > 1 ) {
					echo ' ' . get_avatar( $author->ID, $instance['avatar_size'], '', true ) . ' ';
				}

				echo '<strong>' . esc_html( $author->display_name ) . '</strong>';
				echo '</a>';
			} elseif ( $instance['all'] ) {
				if ( $instance['avatar_size'] > 1 ) {
					echo get_avatar( $author->ID, $instance['avatar_size'], '', true ) . ' ';
				}

				echo '<strong>' . esc_html( $author->display_name ) . '</strong>';
			}

			if ( 0 === (int) $instance['number'] ) {
				echo '</li>';
				continue;
			}

			// Display a short list of recent posts for this author.
			if ( $r->have_posts() ) {
				echo '<ul>';

				while ( $r->have_posts() ) {
					$r->the_post();

					printf(
						'<li><a href="%1$s" title="%2$s"%3$s>%4$s</a></li>',
						esc_url( get_permalink() ),
						esc_attr( wp_kses( get_the_title(), array() ) ),
						( get_queried_object_id() === get_the_ID() ? ' aria-current="page"' : '' ),
						esc_html( wp_kses( get_the_title(), array() ) )
					);
				}

				echo '</ul>';
			}

			echo '</li>';
		}

		echo '</ul>';
		echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		wp_reset_postdata();

		if ( '%BEG_OF_TITLE%' !== $args['before_title'] ) {
			wp_cache_add( $cache_bucket, ob_get_flush(), 'widget' );
		}

		/** This action is documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'authors' );
	}

	/**
	 * Outputs the widget settings form.
	 *
	 * @param array $instance Current settings.
	 */
	public function form( $instance ) {
		$instance = wp_parse_args(
			$instance,
			array(
				'title'       => '',
				'all'         => false,
				'avatar_size' => 48,
				'number'      => 5,
			)
		);

		?>
		<p>
			<label>
				<?php esc_html_e( 'Title:', 'jetpack' ); ?>
				<input class="widefat" name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['title'] ); ?>" />
			</label>
		</p>
		<p>
			<label>
				<input class="checkbox" type="checkbox" <?php checked( $instance['all'] ); ?> name="<?php echo esc_attr( $this->get_field_name( 'all' ) ); ?>" />
				<?php esc_html_e( 'Display all authors (including those who have not written any posts)', 'jetpack' ); ?>
			</label>
		</p>
		<p>
			<label>
				<?php esc_html_e( 'Number of posts to show for each author:', 'jetpack' ); ?>
				<input style="width: 50px; text-align: center;" name="<?php echo esc_attr( $this->get_field_name( 'number' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['number'] ); ?>" />
				<?php esc_html_e( '(at most 10)', 'jetpack' ); ?>
			</label>
		</p>
		<p>
			<label>
				<?php esc_html_e( 'Avatar Size (px):', 'jetpack' ); ?>
				<select name="<?php echo esc_attr( $this->get_field_name( 'avatar_size' ) ); ?>">
					<?php
					foreach ( array(
						'1'   => __( 'No Avatars', 'jetpack' ),
						'16'  => '16x16',
						'32'  => '32x32',
						'48'  => '48x48',
						'96'  => '96x96',
						'128' => '128x128',
					) as $value => $label ) {
						?>
						<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $value, $instance['avatar_size'] ); ?>><?php echo esc_html( $label ); ?></option>
					<?php } ?>
				</select>
			</label>
		</p>
		<?php
	}

	/**
	 * Updates the widget on save and flushes cache.
	 *
	 * @param array $new_instance New widget instance data.
	 * @param array $old_instance Old widget instance data.
	 * @return array
	 */
	public function update( $new_instance, $old_instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$new_instance['title']       = wp_strip_all_tags( $new_instance['title'] );
		$new_instance['all']         = isset( $new_instance['all'] );
		$new_instance['number']      = (int) $new_instance['number'];
		$new_instance['avatar_size'] = (int) $new_instance['avatar_size'];

		self::flush_cache();

		return $new_instance;
	}
}

add_action( 'widgets_init', 'jetpack_register_widget_authors' );
/**
 * Register the Authors widget.
 */
function jetpack_register_widget_authors() {
	register_widget( 'Jetpack_Widget_Authors' );
}
