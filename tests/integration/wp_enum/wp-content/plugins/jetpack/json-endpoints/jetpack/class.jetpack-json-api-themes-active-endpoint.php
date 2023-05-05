<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * GET  /sites/%s/themes/mine => current theme
 * POST /sites/%s/themes/mine => switch theme
 */
class Jetpack_JSON_API_Themes_Active_Endpoint extends Jetpack_JSON_API_Themes_Endpoint {

	/**
	 * Endpoint callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param object $object - The unused $object parameter is for making the method signature compatible with its parent class method.
	 *
	 * @return array|bool|WP_Error
	 */
	public function callback( $path = '', $blog_id = 0, $object = null ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$error = $this->validate_call( $blog_id, 'switch_themes', true );
		if ( is_wp_error( $error ) ) {
			return $error;
		}

		if ( 'POST' === $this->api->method ) {
			return $this->switch_theme();
		} else {
			return $this->get_current_theme();
		}
	}

	/**
	 * Switch the theme.
	 *
	 * @return array|WP_Error
	 */
	protected function switch_theme() {
		$args = $this->input();

		if ( ! isset( $args['theme'] ) || empty( $args['theme'] ) ) {
			return new WP_Error( 'missing_theme', __( 'You are required to specify a theme to switch to.', 'jetpack' ), 400 );
		}

		$theme_slug = $args['theme'];

		if ( ! $theme_slug ) {
			return new WP_Error( 'theme_not_found', __( 'Theme is empty.', 'jetpack' ), 404 );
		}

		/**
		 * Trigger action before the switch theme happens.
		 *
		 * @module json-api
		 *
		 * @since 11.1
		 *
		 * @param string $theme_slug Directory name for the theme.
		 * @param mixed  $args       POST body data, including info about the theme we must switch to.
		 */
		do_action( 'jetpack_pre_switch_theme', $theme_slug, $args );

		$theme = wp_get_theme( $theme_slug );

		if ( ! $theme->exists() ) {
			return new WP_Error( 'theme_not_found', __( 'The specified theme was not found.', 'jetpack' ), 404 );
		}

		if ( ! $theme->is_allowed() ) {
			return new WP_Error( 'theme_not_found', __( 'You are not allowed to switch to this theme', 'jetpack' ), 403 );
		}

		switch_theme( $theme_slug );

		return $this->get_current_theme();
	}

	/**
	 * Get the current theme.
	 *
	 * @return array
	 */
	protected function get_current_theme() {
		return $this->format_theme( wp_get_theme() );
	}
}
