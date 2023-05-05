<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

add_action( 'widgets_init', 'jetpack_gravatar_profile_widget_init' );
/**
 * Register the widget for use in Appearance -> Widgets
 */
function jetpack_gravatar_profile_widget_init() {
	register_widget( 'Jetpack_Gravatar_Profile_Widget' );
}

/**
 * Display a widgetized version of your Gravatar Profile
 * https://blog.gravatar.com/2010/03/26/gravatar-profiles/
 */
class Jetpack_Gravatar_Profile_Widget extends WP_Widget {
	/**
	 * Jetpack_Gravatar_Profile_Widget constructor.
	 */
	public function __construct() {
		parent::__construct(
			'grofile',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', __( 'Gravatar Profile', 'jetpack' ) ),
			array(
				'classname'                   => 'widget-grofile grofile',
				'description'                 => __( 'Display a mini version of your Gravatar Profile', 'jetpack' ),
				'customize_selective_refresh' => true,
			)
		);

		if ( is_admin() ) {
			add_action( 'admin_footer-widgets.php', array( $this, 'admin_script' ) );
		}

		if ( is_customize_preview() ) {
			add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		}
	}

	/**
	 * Display the Widget.
	 *
	 * @see WP_Widget::widget()
	 *
	 * @param array $args     Display arguments.
	 * @param array $instance The settings for the particular instance of the widget.
	 */
	public function widget( $args, $instance ) {
		/**
		 * Fires when an item is displayed on the front end.
		 *
		 * Can be used to track stats about the number of displays for a specific item
		 *
		 * @module widgets, shortcodes
		 *
		 * @since 1.6.0
		 *
		 * @param string widget_view Item type (e.g. widget, or embed).
		 * @param string grofile     Item description (e.g. grofile, goodreads).
		 */
		do_action( 'jetpack_stats_extra', 'widget_view', 'grofile' );

		$instance = wp_parse_args(
			$instance,
			array(
				'title' => '',
				'email' => '',
			)
		);

		/** This filter is documented in core/src/wp-includes/default-widgets.php */
		$title = apply_filters( 'widget_title', $instance['title'] );

		if ( ! $instance['email'] ) {
			if ( current_user_can( 'edit_theme_options' ) ) {
				echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				if ( ! empty( $title ) ) {
					echo $args['before_title'] . $title . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				}
				echo '<p>' . wp_kses(
					sprintf(
						/* translators: %s is a link to the widget settings page. */
						__( 'You need to select what to show in this <a href="%s">Gravatar Profile widget</a>.', 'jetpack' ),
						admin_url( 'widgets.php' )
					),
					array(
						'a' => array(
							'href' => true,
						),
					)
				) . '</p>';
				echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			return;
		}

		echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		if ( ! empty( $title ) ) {
			echo $args['before_title'] . $title . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		$profile = $this->get_profile( $instance['email'] );

		if ( ! empty( $profile ) ) {
			$profile      = wp_parse_args(
				$profile,
				array(
					'thumbnailUrl' => '',
					'profileUrl'   => '',
					'displayName'  => '',
					'aboutMe'      => '',
					'urls'         => array(),
					'accounts'     => array(),
				)
			);
			$gravatar_url = add_query_arg( 's', 320, $profile['thumbnailUrl'] ); // The default grav returned by grofiles is super small.

			// Enqueue front end assets.
			$this->enqueue_scripts();

			?>
			<img src="<?php echo esc_url( $gravatar_url ); ?>" class="grofile-thumbnail no-grav" alt="<?php echo esc_attr( $profile['displayName'] ); ?>" />
			<div class="grofile-meta">
				<h4><a href="<?php echo esc_url( $profile['profileUrl'] ); ?>"><?php echo esc_html( $profile['displayName'] ); ?></a></h4>
				<p><?php echo wp_kses_post( $profile['aboutMe'] ); ?></p>
			</div>

			<?php

			if ( $instance['show_personal_links'] ) {
				$this->display_personal_links( (array) $profile['urls'] );
			}

			if ( $instance['show_account_links'] ) {
				$this->display_accounts( (array) $profile['accounts'] );
			}

			?>

			<p><a href="<?php echo esc_url( $profile['profileUrl'] ); ?>" class="grofile-full-link">
				<?php
				echo esc_html(
					/**
					 * Filter the Gravatar Profile widget's profile link title.
					 *
					 * @module widgets
					 *
					 * @since 2.8.0
					 *
					 * @param string $str Profile link title.
					 */
					apply_filters(
						'jetpack_gravatar_full_profile_title',
						__( 'View Full Profile &rarr;', 'jetpack' )
					)
				);
				?>
			</a></p>

			<?php
		} elseif ( current_user_can( 'edit_theme_options' ) ) {
			echo '<p>' . esc_html__( 'Error loading profile', 'jetpack' ) . '</p>';
		}

		echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * Displays the "Personal Links" section.
	 *
	 * @param array $personal_links Array of links.
	 */
	public function display_personal_links( $personal_links = array() ) {
		if ( empty( $personal_links ) ) {
			return;
		}
		?>

			<h4>
			<?php
			echo esc_html(
				apply_filters(
					/**
					 * Filter the Gravatar Profile widget's "Personal Links" section title.
					 *
					 * @module widgets
					 *
					 * @since 2.8.0
					 *
					 * @param string $str "Personal Links" section title.
					 */
					'jetpack_gravatar_personal_links_title',
					__( 'Personal Links', 'jetpack' )
				)
			);
			?>
				</h4>
			<ul class="grofile-urls grofile-links">

			<?php foreach ( $personal_links as $personal_link ) : ?>
				<li>
					<a href="<?php echo esc_url( $personal_link['value'] ); ?>">
						<?php
							$link_title = ( ! empty( $personal_link['title'] ) ) ? $personal_link['title'] : $personal_link['value'];
							echo esc_html( $link_title );
						?>
					</a>
				</li>
			<?php endforeach; ?>
			</ul>

		<?php
	}

	/**
	 * Displays the "Verified Services" accounts.
	 *
	 * @param array $accounts Array of social accounts.
	 */
	public function display_accounts( $accounts = array() ) {
		if ( empty( $accounts ) ) {
			return;
		}
		?>

		<h4>
		<?php
		echo esc_html(
			/**
			 * Filter the Gravatar Profile widget's "Verified Services" section title.
			 *
			 * @module widgets
			 *
			 * @since 2.8.0
			 *
			 * @param string $str "Verified Services" section title.
			 */
			apply_filters(
				'jetpack_gravatar_verified_services_title',
				__( 'Verified Services', 'jetpack' )
			)
		);
		?>
			</h4>
		<ul class="grofile-urls grofile-accounts">

		<?php
		foreach ( $accounts as $account ) :
			if ( 'true' !== $account['verified'] ) {
				continue;
			}

			$sanitized_service_name = $this->get_sanitized_service_name( $account['shortname'] );
			$link_title             = sprintf(
				/* translators: %1$s: service username. %2$s: service name ( Facebook, Twitter, etc.) */
				_x( '%1$s on %2$s', '1: User Name, 2: Service Name (Facebook, Twitter, ...)', 'jetpack' ),
				esc_html( $account['display'] ),
				esc_html( $sanitized_service_name )
			);
			?>

			<li>
				<a href="<?php echo esc_url( $account['url'] ); ?>" title="<?php echo esc_html( $link_title ); ?>">
					<span class="grofile-accounts-logo grofile-accounts-<?php echo esc_attr( $account['shortname'] ); ?> accounts_<?php echo esc_attr( $account['shortname'] ); ?>"></span>
				</a>
			</li>

		<?php endforeach; ?>
		</ul>

		<?php
	}

	/**
	 * Enqueue CSS and JavaScript.
	 *
	 * @since 4.0.0
	 */
	public function enqueue_scripts() {
		wp_enqueue_style(
			'gravatar-profile-widget',
			plugins_url( 'gravatar-profile.css', __FILE__ ),
			array(),
			'20120711'
		);

		wp_enqueue_style(
			'gravatar-card-services',
			'https://secure.gravatar.com/css/services.css',
			array(),
			defined( 'GROFILES__CACHE_BUSTER' ) ? GROFILES__CACHE_BUSTER : gmdate( 'YW' )
		);
	}

	/**
	 * Outputs the widget settings form.
	 *
	 * @param array $instance Current settings.
	 */
	public function form( $instance ) {
		$title               = isset( $instance['title'] ) ? $instance['title'] : '';
		$email               = isset( $instance['email'] ) ? $instance['email'] : '';
		$email_user          = isset( $instance['email_user'] ) ? $instance['email_user'] : get_current_user_id();
		$show_personal_links = isset( $instance['show_personal_links'] ) ? (bool) $instance['show_personal_links'] : '';
		$show_account_links  = isset( $instance['show_account_links'] ) ? (bool) $instance['show_account_links'] : '';
		$profile_url         = 'https://gravatar.com/profile/edit';

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$profile_url = admin_url( 'profile.php' );

			if ( isset( $_REQUEST['calypso'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$profile_url = 'https://wordpress.com/me';
			}
		}
		?>
		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>">
				<?php esc_html_e( 'Title', 'jetpack' ); ?> <input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" type="text" value="<?php echo esc_attr( $title ); ?>" />
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'email_user' ) ); ?>">
				<?php esc_html_e( 'Select a user or pick "custom" and enter a custom email address.', 'jetpack' ); ?>
				<br />

				<?php
				wp_dropdown_users(
					array(
						'show_option_none' => __( 'Custom', 'jetpack' ),
						'selected'         => $email_user,
						'name'             => $this->get_field_name( 'email_user' ),
						'id'               => $this->get_field_id( 'email_user' ),
						'class'            => 'gravatar-profile-user-select',
					)
				);
				?>
			</label>
		</p>

		<p class="gprofile-email-container <?php echo empty( $email_user ) || -1 === (int) $email_user ? '' : 'hidden'; ?>">
			<label for="<?php echo esc_attr( $this->get_field_id( 'email' ) ); ?>"><?php esc_html_e( 'Custom Email Address', 'jetpack' ); ?>
				<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'email' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'email' ) ); ?>" type="text" value="<?php echo esc_attr( $email ); ?>" />
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'show_personal_links' ) ); ?>">
				<input type="checkbox" name="<?php echo esc_attr( $this->get_field_name( 'show_personal_links' ) ); ?>" id="<?php echo esc_attr( $this->get_field_id( 'show_personal_links' ) ); ?>" <?php checked( $show_personal_links ); ?> />
				<?php esc_html_e( 'Show Personal Links', 'jetpack' ); ?>
				<br />
				<small><?php esc_html_e( 'Links to your websites, blogs, or any other sites that help describe who you are.', 'jetpack' ); ?></small>
			</label>
		</p>

		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'show_account_links' ) ); ?>">
				<input type="checkbox" name="<?php echo esc_attr( $this->get_field_name( 'show_account_links' ) ); ?>" id="<?php echo esc_attr( $this->get_field_id( 'show_account_links' ) ); ?>" <?php checked( $show_account_links ); ?> />
				<?php esc_html_e( 'Show Account Links', 'jetpack' ); ?>
				<br />
				<small><?php esc_html_e( 'Links to services that you use across the web.', 'jetpack' ); ?></small>
			</label>
		</p>

		<p><a href="<?php echo esc_url( $profile_url ); ?>" target="_blank" title="<?php esc_attr_e( 'Opens in new window', 'jetpack' ); ?>"><?php esc_html_e( 'Edit Your Profile', 'jetpack' ); ?></a> | <a href="https://gravatar.com" target="_blank" title="<?php esc_attr_e( 'Opens in new window', 'jetpack' ); ?>"><?php esc_html_e( "What's a Gravatar?", 'jetpack' ); ?></a></p>

		<?php
	}

	/**
	 * Inline admin script.
	 */
	public function admin_script() {
		?>
		<script>
		jQuery( function( $ ) {
			$( '.wrap' ).on( 'change', '.gravatar-profile-user-select', function() {
				var $input = $(this).closest('.widget-inside').find('.gprofile-email-container');
				if ( '-1' === this.value.toLowerCase() ) {
					$input.show();
				} else {
					$input.hide();
				}
			});
		} );
		</script>
		<?php
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

		$instance['title']               = isset( $new_instance['title'] ) ? wp_kses( $new_instance['title'], array() ) : '';
		$instance['email']               = isset( $new_instance['email'] ) ? wp_kses( $new_instance['email'], array() ) : '';
		$instance['email_user']          = isset( $new_instance['email_user'] ) ? (int) $new_instance['email_user'] : -1;
		$instance['show_personal_links'] = isset( $new_instance['show_personal_links'] ) ? (bool) $new_instance['show_personal_links'] : false;
		$instance['show_account_links']  = isset( $new_instance['show_account_links'] ) ? (bool) $new_instance['show_account_links'] : false;

		if ( $instance['email_user'] > 0 ) {
			$user              = get_userdata( $instance['email_user'] );
			$instance['email'] = $user->user_email;
		}

		$hashed_email = md5( strtolower( trim( $instance['email'] ) ) );
		$cache_key    = 'grofile-' . $hashed_email;
		delete_transient( $cache_key );

		return $instance;
	}

	/**
	 * Get the Gravatar profile for a given email address.
	 *
	 * @param string $email Email address.
	 */
	private function get_profile( $email ) {
		$hashed_email = md5( strtolower( trim( $email ) ) );
		$cache_key    = 'grofile-' . $hashed_email;
		$profile      = get_transient( $cache_key );

		if ( ! $profile ) {
			$profile_url = sprintf(
				'https://secure.gravatar.com/%s.json',
				$hashed_email
			);

			$expire        = 300;
			$response      = wp_remote_get(
				esc_url_raw( $profile_url ),
				array( 'User-Agent' => 'WordPress.com Gravatar Profile Widget' )
			);
			$response_code = wp_remote_retrieve_response_code( $response );
			if ( 200 === $response_code ) {
				$profile = wp_remote_retrieve_body( $response );
				$profile = json_decode( $profile, true );

				if ( is_array( $profile ) && ! empty( $profile['entry'] ) && is_array( $profile['entry'] ) ) {
					$expire  = 900; // Cache for 15 minutes.
					$profile = $profile['entry'][0];
				} else {
					// Something strange happened.  Cache for 5 minutes.
					$profile = array();
				}
			} else {
				$expire  = 900; // Cache for 15 minutes.
				$profile = array();
			}

			set_transient( $cache_key, $profile, $expire );
		}
		return $profile;
	}

	/**
	 * Return properly capitalized service name.
	 *
	 * @param string $shortname The service.
	 *
	 * @return string
	 */
	private function get_sanitized_service_name( $shortname ) {
		// Some services have stylized or mixed cap names *cough* WP *cough*.
		switch ( $shortname ) {
			case 'friendfeed':
				return 'FriendFeed';
			case 'linkedin':
				return 'LinkedIn';
			case 'yahoo':
				return 'Yahoo!';
			case 'youtube':
				return 'YouTube';
			// phpcs:ignore WordPress.WP.CapitalPDangit
			case 'wordpress':
				return 'WordPress';
			case 'tripit':
				return 'TripIt';
			case 'myspace':
				return 'MySpace';
			case 'foursquare':
				return 'foursquare';
			case 'google':
				return 'Google+';
			default:
				// Others don't.
				$shortname = ucwords( $shortname );
		}
		return $shortname;
	}
}
