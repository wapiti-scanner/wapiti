<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Theme Tools: Social Links.
 *
 * This feature will only be activated for themes that declare their support.
 * This can be done by adding code similar to the following during the
 * 'after_setup_theme' action:
 *
 * add_theme_support( 'social-links', array(
 *     'facebook', 'twitter', 'linkedin', 'tumblr',
 * ) );
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Init Social_Links if the theme declares support.
 */
function jetpack_theme_supports_social_links() {
	if ( current_theme_supports( 'social-links' ) && function_exists( 'publicize_init' ) ) {
		new Social_Links();
	}
}
add_action( 'init', 'jetpack_theme_supports_social_links', 30 );

if ( ! class_exists( 'Social_Links' ) ) {

	/**
	 * Social_Links main class.
	 */
	class Social_Links {

		/**
		 * The links the user set for each service.
		 *
		 * @var array
		 */
		private $links;

		/**
		 * A Publicize object.
		 *
		 * @var Publicize
		 */
		private $publicize;

		/**
		 * An array with all services that are supported by both Publicize and the
		 * currently active theme.
		 *
		 * @var array
		 */
		private $services = array();

		/**
		 * An array of the services the theme supports
		 *
		 * @var array
		 */
		private $theme_supported_services = array();

		/**
		 * Constructor.
		 */
		public function __construct() {
			$theme_support = get_theme_support( 'social-links' );

			/*
			An array of named arguments must be passed as the second parameter
			 * of add_theme_support().
			 */
			if ( empty( $theme_support[0] ) ) {
				return;
			}

			$this->theme_supported_services = $theme_support[0];
			$this->links                    = Jetpack_Options::get_option( 'social_links', array() );

			$this->admin_setup();

			add_filter( 'jetpack_has_social_links', array( $this, 'has_social_links' ) );
			add_filter( 'jetpack_get_social_links', array( $this, 'get_social_links' ) );

			foreach ( $theme_support[0] as $service ) {
				add_filter( "pre_option_jetpack-$service", array( $this, 'get_social_link_filter' ) ); // - `get_option( 'jetpack-service' );`
				add_filter( "theme_mod_jetpack-$service", array( $this, 'get_social_link_filter' ) ); // - `get_theme_mod( 'jetpack-service' );`
			}
		}

		/**
		 * Init the admin setup.
		 */
		public function admin_setup() {
			if ( ! current_user_can( 'manage_options' ) ) {
				return;
			}

			if ( ! is_admin() && ! $this->is_customize_preview() ) {
				return;
			}

			$this->publicize    = publicize_init();
			$publicize_services = $this->publicize->get_services( 'connected' );
			$this->services     = array_intersect( array_keys( $publicize_services ), $this->theme_supported_services );

			add_action( 'publicize_connected', array( $this, 'check_links' ), 20 );
			add_action( 'publicize_disconnected', array( $this, 'check_links' ), 20 );
			add_action( 'customize_register', array( $this, 'customize_register' ) );
			add_filter( 'sanitize_option_jetpack_options', array( $this, 'sanitize_link' ) );
		}

		/**
		 * Compares the currently saved links with the connected services and removes
		 * links from services that are no longer connected.
		 *
		 * @return void
		 */
		public function check_links() {
			$active_links = array_intersect_key( $this->links, array_flip( $this->services ) );

			if ( $active_links !== $this->links ) {
				$this->links = $active_links;
				Jetpack_Options::update_option( 'social_links', $active_links );
			}
		}

		/**
		 * Add social link dropdown to the Customizer.
		 *
		 * @param WP_Customize_Manager $wp_customize Theme Customizer object.
		 */
		public function customize_register( $wp_customize ) {
			$wp_customize->add_section(
				'jetpack_social_links',
				array(
					'title'    => esc_html__( 'Connect', 'jetpack' ),
					'priority' => 35,
				)
			);

			foreach ( array_keys( $this->publicize->get_services( 'all' ) ) as $service ) {
				$choices = $this->get_customize_select( $service );

				if ( empty( $choices ) ) {
					continue;
				}

				$wp_customize->add_setting(
					"jetpack_options[social_links][$service]",
					array(
						'type'    => 'option',
						'default' => '',
					)
				);

				$wp_customize->add_control(
					"jetpack-$service",
					array(
						'label'    => $this->publicize->get_service_label( $service ),
						'section'  => 'jetpack_social_links',
						'settings' => "jetpack_options[social_links][$service]",
						'type'     => 'select',
						'choices'  => $choices,
					)
				);
			}
		}

		/**
		 * Sanitizes social links.
		 *
		 * @param array $option The incoming values to be sanitized.
		 * @returns array
		 */
		public function sanitize_link( $option ) {
			foreach ( $this->services as $service ) {
				if ( ! empty( $option['social_links'][ $service ] ) ) {
					$option['social_links'][ $service ] = esc_url_raw( $option['social_links'][ $service ] );
				} else {
					unset( $option['social_links'][ $service ] );
				}
			}

			return $option;
		}

		/**
		 * Returns whether there are any social links set.
		 *
		 * @returns bool
		 */
		public function has_social_links() {
			return ! empty( $this->links );
		}

		/**
		 * Return available social links.
		 *
		 * @returns array
		 */
		public function get_social_links() {
			return $this->links;
		}

		/**
		 * Short-circuits get_option and get_theme_mod calls.
		 *
		 * @param string $link The incoming value to be replaced.
		 * @returns string $link The social link that we've got.
		 */
		public function get_social_link_filter( $link ) {
			if ( preg_match( '/_jetpack-(.+)$/i', current_filter(), $matches ) && ! empty( $this->links[ $matches[1] ] ) ) {
				return $this->links[ $matches[1] ];
			}

			return $link;
		}

		/**
		 * Puts together an array of choices for a specific service.
		 *
		 * @param string $service The social service.
		 * @return array An associative array with profile links and display names.
		 */
		private function get_customize_select( $service ) {
			$choices = array(
				'' => __( '&mdash; Select &mdash;', 'jetpack' ),
			);

			if ( isset( $this->links[ $service ] ) ) {
				$choices[ $this->links[ $service ] ] = $this->links[ $service ];
			}

			$connected_services = $this->publicize->get_services( 'connected' );
			if ( isset( $connected_services[ $service ] ) ) {
				foreach ( $connected_services[ $service ] as $c ) {
					$profile_link = $this->publicize->get_profile_link( $service, $c );

					if ( false === $profile_link ) {
						continue;
					}

					$choices[ $profile_link ] = $this->publicize->get_display_name( $service, $c );
				}
			}

			if ( 1 === count( $choices ) ) {
				return array();
			}

			return $choices;
		}

		/**
		 * Back-compat function for versions prior to 4.0.
		 */
		private function is_customize_preview() {
			global $wp_customize;
			return is_a( $wp_customize, 'WP_Customize_Manager' ) && $wp_customize->is_preview();
		}
	}

} // - end if ( ! class_exists( 'Social_Links' )
