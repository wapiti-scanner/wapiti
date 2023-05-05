<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Redirect;

/**
 * Disable direct access/execution to/of the widget code.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Jetpack_My_Community_Widget displays community members of this site.
 *
 * A community member is a WordPress.com user that liked or commented on an entry or subscribed to the site.
 * Requires WordPress.com connection to work. Otherwise it won't be visible in Widgets screen in admin.
 */
class Jetpack_My_Community_Widget extends WP_Widget {
	/**
	 * Transient expiration time.
	 *
	 * @var int $expiration
	 */
	public static $expiration = 600;

	/**
	 * Default widget title.
	 *
	 * @var string $default_title
	 */
	public $default_title;

	/**
	 * Registers the widget with WordPress.
	 */
	public function __construct() {
		parent::__construct(
			'jetpack_my_community', // Base ID.
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', esc_html__( 'My Community', 'jetpack' ) ),
			array(
				'description'                 => esc_html__( "Display members of your site's community.", 'jetpack' ),
				'customize_selective_refresh' => true,
			)
		);

		if ( is_active_widget( false, false, $this->id_base ) || is_active_widget( false, false, 'monster' ) || is_customize_preview() ) {
			add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_style' ) );
		}

		$this->default_title = esc_html__( 'Community', 'jetpack' );

		add_filter( 'widget_types_to_hide_from_legacy_widget_block', array( $this, 'hide_widget_in_block_editor' ) );
	}

	/**
	 * Remove the "My Community" widget from the Legacy Widget block
	 *
	 * @param array $widget_types List of widgets that are currently removed from the Legacy Widget block.
	 * @return array $widget_types New list of widgets that will be removed.
	 */
	public function hide_widget_in_block_editor( $widget_types ) {
		$widget_types[] = 'jetpack_my_community';
		return $widget_types;
	}

	/**
	 * Enqueue stylesheet for grid layout.
	 */
	public function enqueue_style() {
		wp_register_style( 'jetpack-my-community-widget', plugins_url( 'my-community/style.css', __FILE__ ), array(), '20160129' );
		wp_enqueue_style( 'jetpack-my-community-widget' );
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
		$title = isset( $instance['title'] ) ? $instance['title'] : false;
		if ( false === $title ) {
			$title = $this->default_title;
		}

		$number = isset( $instance['number'] ) ? (int) $instance['number'] : 10;
		if ( ! in_array( $number, array( 10, 50 ), true ) ) {
			$number = 10;
		}

		$include_likers     = isset( $instance['include_likers'] ) ? (bool) $instance['include_likers'] : true;
		$include_followers  = isset( $instance['include_followers'] ) ? (bool) $instance['include_followers'] : true;
		$include_commenters = isset( $instance['include_commenters'] ) ? (bool) $instance['include_commenters'] : true;
		?>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"><?php esc_html_e( 'Title:', 'jetpack' ); ?></label>
			<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" type="text" value="<?php echo esc_attr( $title ); ?>" />
		</p>

		<p>
			<label><?php esc_html_e( 'Show a maximum of', 'jetpack' ); ?></label>
		</p>
		<ul>
			<li><label><input id="<?php echo esc_attr( $this->get_field_id( 'number' ) ); ?>-few"  name="<?php echo esc_attr( $this->get_field_name( 'number' ) ); ?>" type="radio" value="10" <?php checked( '10', $number ); ?> /> <?php esc_html_e( '10 community members', 'jetpack' ); ?></label></li>
			<li><label><input id="<?php echo esc_attr( $this->get_field_id( 'number' ) ); ?>-lots" name="<?php echo esc_attr( $this->get_field_name( 'number' ) ); ?>" type="radio" value="50" <?php checked( '50', $number ); ?> /> <?php esc_html_e( '50 community members', 'jetpack' ); ?></label></li>
		</ul>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'include_likers' ) ); ?>">
				<input type="checkbox" class="checkbox"  id="<?php echo esc_attr( $this->get_field_id( 'include_likers' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'include_likers' ) ); ?>" value="1" <?php checked( $include_likers, 1 ); ?> />
				<?php esc_html_e( 'Include activity from likers', 'jetpack' ); ?>
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'include_followers' ) ); ?>">
				<input type="checkbox" class="checkbox"  id="<?php echo esc_attr( $this->get_field_id( 'include_followers' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'include_followers' ) ); ?>" value="1" <?php checked( $include_followers, 1 ); ?> />
				<?php esc_html_e( 'Include activity from followers', 'jetpack' ); ?>
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'include_commenters' ) ); ?>">
				<input type="checkbox" class="checkbox"  id="<?php echo esc_attr( $this->get_field_id( 'include_commenters' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'include_commenters' ) ); ?>" value="1" <?php checked( $include_commenters, 1 ); ?> />
				<?php esc_html_e( 'Include activity from commenters', 'jetpack' ); ?>
			</label>
		</p>

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
		if ( $instance['title'] === $this->default_title ) {
			$instance['title'] = false; // Store as false in case of language change.
		}

		$instance['number'] = (int) $new_instance['number'];
		if ( ! in_array( $instance['number'], array( 10, 50 ), true ) ) {
			$instance['number'] = 10;
		}

		$instance['include_likers']     = (bool) $new_instance['include_likers'];
		$instance['include_followers']  = (bool) $new_instance['include_followers'];
		$instance['include_commenters'] = (bool) $new_instance['include_commenters'];

		delete_transient( "$this->id-v2-{$instance['number']}" . (int) $instance['include_likers'] . (int) $instance['include_followers'] . (int) $instance['include_commenters'] );

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
		$instance = wp_parse_args(
			$instance,
			array(
				'title'              => false,
				'number'             => true,
				'include_likers'     => true,
				'include_followers'  => true,
				'include_commenters' => true,
			)
		);

		$title = $instance['title'];

		if ( false === $title ) {
			$title = $this->default_title;
		}

		echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This filter is documented in wp-includes/widgets/class-wp-widget-pages.php */
		$title = apply_filters( 'widget_title', $title );
		if ( ! empty( $title ) ) {
			echo $args['before_title'] . $title . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		$transient_name = "$this->id-v2-{$instance['number']}" . (int) $instance['include_likers'] . (int) $instance['include_followers'] . (int) $instance['include_commenters'];

		$my_community = get_transient( $transient_name );

		if ( empty( $my_community ) ) {
			$my_community = $this->get_community( $instance );

			set_transient( $transient_name, $my_community, self::$expiration );
		}

		echo $my_community; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This action is documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'my_community' );
	}

	/**
	 * Initiate request and render the response.
	 *
	 * @since 4.0
	 *
	 * @param array $query Saved widget values from database.
	 *
	 * @return string
	 */
	private function get_community( $query ) {
		$members = $this->fetch_remote_community( $query );

		if ( ! empty( $members ) ) {

			$my_community = '<div class="widgets-multi-column-grid"><ul>';

			foreach ( $members as $member ) {
				$my_community .= sprintf(
					'<li><a href="%s" title="%s"><img alt="%s" src="%s" class="avatar avatar-48" height="48" width="48"></a></li>',
					esc_url( $member->profile_URL ), // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
					esc_attr( $member->name ),
					esc_attr( $member->name ),
					esc_url( $member->avatar_URL ) // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				);
			}

			$my_community .= '</ul></div>';

		} elseif ( current_user_can( 'edit_theme_options' ) ) {
			$my_community = '<p>' . wp_kses(
				sprintf(
					/* Translators: 1. link to the widgets settings screen. 2. link to support document. */
					__( 'There are no users to display in this <a href="%1$s">My Community widget</a>. <a href="%2$s">Want more traffic?</a>', 'jetpack' ),
					admin_url( 'widgets.php' ),
					esc_url( Redirect::get_url( 'jetpack-support-getting-more-views-and-traffic' ) )
				),
				array( 'a' => array( 'href' => true ) )
			) . '</p>';
		} else {
			$my_community = '<p>' . esc_html__( "I'm just starting out; leave me a comment or a like :)", 'jetpack' ) . '</p>';
		}

		return $my_community;
	}

	/**
	 * Request community members to WordPress.com endpoint.
	 *
	 * @since 4.0
	 *
	 * @param array $query Saved widget values from database.
	 *
	 * @return array
	 */
	private function fetch_remote_community( $query ) {
		$jetpack_blog_id = Jetpack_Options::get_option( 'id' );
		$url             = add_query_arg(
			array(
				'number'     => $query['number'],
				'likers'     => (int) $query['include_likers'],
				'followers'  => (int) $query['include_followers'],
				'commenters' => (int) $query['include_commenters'],
			),
			"https://public-api.wordpress.com/rest/v1.1/sites/$jetpack_blog_id/community"
		);
		$response        = wp_remote_get( $url );
		$response_body   = wp_remote_retrieve_body( $response );

		if ( empty( $response_body ) ) {
			return array();
		}

		$response_body = json_decode( $response_body );

		if ( isset( $response_body->users ) ) {
			return $response_body->users;
		}

		return array();
	}
}

/**
 * If site is connected to WordPress.com, register the widget.
 *
 * @since 4.0
 */
function jetpack_my_community_init() {
	if ( Jetpack::is_connection_ready() ) {
		register_widget( 'Jetpack_My_Community_Widget' );
	}
}
add_action( 'widgets_init', 'jetpack_my_community_init' );
