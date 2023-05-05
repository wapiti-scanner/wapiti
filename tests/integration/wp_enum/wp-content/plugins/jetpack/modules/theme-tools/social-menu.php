<?php
/**
 * Social Menu.
 *
 * This feature will only be activated for themes that declare their support.
 * This can be done by adding code similar to the following during the
 * 'after_setup_theme' action:
 *
 * add_theme_support( 'jetpack-social-menu' );
 *
 * @package automattic/jetpack
 */

/**
 * Activate the Social Menu plugin.
 *
 * @uses current_theme_supports()
 */
function jetpack_social_menu_init() {
	// Only load our code if our theme declares support
	if ( ! current_theme_supports( 'jetpack-social-menu' ) ) {
		return;
	}

	/*
	 * Social Menu description.
	 *
	 * Rename the social menu description.
	 *
	 * @module theme-tools
	 *
	 * @since 3.9.0
	 *
	 * @param string $social_menu_description Social Menu description
	 */
	$social_menu_description = apply_filters( 'jetpack_social_menu_description', __( 'Social Menu', 'jetpack' ) );

	// Register a new menu location
	register_nav_menus(
		array(
			'jetpack-social-menu' => esc_html( $social_menu_description ),
		)
	);

	// Enqueue CSS
	add_action( 'wp_enqueue_scripts', 'jetpack_social_menu_style' );

	// Load SVG icons related functions and filters
	if ( 'svg' === jetpack_social_menu_get_type() ) {
		require __DIR__ . '/social-menu/icon-functions.php';
	}
}
add_action( 'after_setup_theme', 'jetpack_social_menu_init', 99 );
add_action( 'restapi_theme_init', 'jetpack_social_menu_init' );

/**
 * Return the type of menu the theme is using.
 *
 * @uses get_theme_support()
 * @return null|string $menu_type
 */
function jetpack_social_menu_get_type() {
	$options = get_theme_support( 'jetpack-social-menu' );

	if ( ! $options ) {
		$menu_type = null;
	} else {
		$menu_type = 'genericons';
		if ( is_array( $options ) && isset( $options[0] ) ) {
			$menu_type = ( in_array( $options[0], array( 'genericons', 'svg' ), true ) ) ? $options[0] : 'genericons';
		}
	}

	return $menu_type;
}

/**
 * Function to enqueue the CSS.
 */
function jetpack_social_menu_style() {
	$menu_type = jetpack_social_menu_get_type();

	if ( ! $menu_type ) {
		return;
	}

	$deps = ( 'genericons' === $menu_type ) ? array( 'genericons' ) : null;

	if ( has_nav_menu( 'jetpack-social-menu' ) ) {
		wp_enqueue_style( 'jetpack-social-menu', plugins_url( 'social-menu/social-menu.css', __FILE__ ), $deps, '1.0' );
	}
}

/**
 * Create the function for the menu.
 */
function jetpack_social_menu() {
	if ( has_nav_menu( 'jetpack-social-menu' ) ) :
		$menu_type  = jetpack_social_menu_get_type();
		$link_after = '</span>';

		if ( 'svg' === $menu_type ) {
			$link_after .= jetpack_social_menu_get_svg( array( 'icon' => 'chain' ) );
		} ?>
		<nav class="jetpack-social-navigation jetpack-social-navigation-<?php echo esc_attr( $menu_type ); ?>" aria-label="<?php esc_html_e( 'Social Links Menu', 'jetpack' ); ?>">
			<?php
				wp_nav_menu(
					array(
						'theme_location' => 'jetpack-social-menu',
						'link_before'    => '<span class="screen-reader-text">',
						'link_after'     => $link_after,
						'depth'          => 1,
					)
				);
			?>
		</nav><!-- .jetpack-social-navigation -->
		<?php
	endif;
}
