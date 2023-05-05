<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Themes delete endpoint class.
 * POST  /sites/%s/plugins/%s/delete
 */
class Jetpack_JSON_API_Themes_Delete_Endpoint extends Jetpack_JSON_API_Themes_Endpoint {

	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'delete_themes';

	/**
	 * The action.
	 *
	 * @var string
	 */
	protected $action = 'delete';

	/**
	 * Delete the theme.
	 *
	 * @return bool|WP_Error
	 */
	protected function delete() {

		foreach ( $this->themes as $theme ) {

			// Don't delete an active child theme
			if ( is_child_theme() && $theme === get_stylesheet() ) {
				$error                        = 'You cannot delete a theme while it is active on the main site.';
				$this->log[ $theme ]['error'] = $error;
				continue;
			}

			if ( $theme === get_template() ) {
				$error                        = 'You cannot delete a theme while it is active on the main site.';
				$this->log[ $theme ]['error'] = $error;
				continue;
			}

			/**
			 * Filters whether to use an alternative process for deleting a WordPress.com theme.
			 * The alternative process can be executed during the filter.
			 *
			 * The filter can also return an instance of WP_Error; in which case the endpoint response will
			 * contain this error.
			 *
			 * @module json-api
			 *
			 * @since 4.4.2
			 *
			 * @param bool   $use_alternative_delete_method Whether to use the alternative method of deleting
			 *                                              a WPCom theme.
			 * @param string $theme_slug                    Theme name (slug). If it is a WPCom theme,
			 *                                              it should be suffixed with `-wpcom`.
			 */
			$result = apply_filters( 'jetpack_wpcom_theme_delete', false, $theme );

			if ( ! $result ) {
				$result = delete_theme( $theme );
			}

			if ( is_wp_error( $result ) ) {
				$error                        = $result->get_error_messages();
				$this->log[ $theme ]['error'] = $error;
			} else {
				$this->log[ $theme ][] = 'Theme deleted';
			}
		}

		if ( ! $this->bulk && isset( $error ) ) {
			return new WP_Error( 'delete_theme_error', $error, 400 );
		}

		return true;
	}

}
