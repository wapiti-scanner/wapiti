<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Base class for working with themes, has useful helper functions.
 */
abstract class Jetpack_JSON_API_Themes_Endpoint extends Jetpack_JSON_API_Endpoint {

	/**
	 * The themes.
	 *
	 * @var array
	 */
	protected $themes = array();

	/**
	 * If we're working in bulk.
	 *
	 * @var boolean
	 */
	protected $bulk = true;

	/**
	 * The log.
	 *
	 * @var array
	 */
	protected $log;

	/**
	 * The current theme ID.
	 *
	 * @var int
	 */
	protected $current_theme_id;

	/**
	 * The response format.
	 *
	 * @var array
	 */
	public static $_response_format = array( // phpcs:ignore PSR2.Classes.PropertyDeclaration.Underscore
		'id'                     => '(string) The theme\'s ID.',
		'screenshot'             => '(string) A theme screenshot URL',
		'name'                   => '(string) The name of the theme.',
		'theme_uri'              => '(string) The URI of the theme\'s webpage.',
		'description'            => '(string) A description of the theme.',
		'author'                 => '(string) The author of the theme.',
		'author_uri'             => '(string) The website of the theme author.',
		'tags'                   => '(array) Tags indicating styles and features of the theme.',
		'log'                    => '(array) An array of log strings',
		'update'                 => '(array|null) An object containing information about the available update if there is an update available, null otherwise.',
		'autoupdate'             => '(bool) Whether the theme is automatically updated',
		'autoupdate_translation' => '(bool) Whether the theme is automatically updating translations',
	);

	/**
	 * The result.
	 */
	protected function result() {

		$themes = $this->get_themes();

		if ( ! $this->bulk && ! empty( $themes ) ) {
			return array_pop( $themes );
		}

		return array( 'themes' => $themes );
	}

	/**
	 * Walks through either the submitted theme or list of themes and creates the global array
	 *
	 * @param string $theme - the theme URL.
	 *
	 * @return bool|WP_Error
	 */
	protected function validate_input( $theme ) {
		$args = $this->input();
		// lets set what themes were requested, and validate them
		if ( ! isset( $theme ) || empty( $theme ) ) {

			if ( ! $args['themes'] || empty( $args['themes'] ) ) {
				return new WP_Error( 'missing_theme', __( 'You are required to specify a theme to update.', 'jetpack' ), 400 );
			}
			if ( is_array( $args['themes'] ) ) {
				$this->themes = $args['themes'];
			} else {
				$this->themes[] = $args['themes'];
			}
		} else {
			$this->themes[] = urldecode( $theme );
			$this->bulk     = false;
		}

		$error = $this->validate_themes();
		if ( is_wp_error( $error ) ) {
			return $error;
		}

		return parent::validate_input( $theme );
	}

	/**
	 * Walks through submitted themes to make sure they are valid
	 *
	 * @return bool|WP_Error
	 */
	protected function validate_themes() {
		foreach ( $this->themes as $theme ) {
			$error = wp_get_theme( $theme )->errors();
			if ( is_wp_error( $error ) ) {
				return new WP_Error( 'unknown_theme', $error->get_error_messages(), 404 );
			}
		}
		return true;
	}

	/**
	 * Format a theme for the public API
	 *
	 * @param  object $theme WP_Theme object.
	 * @return array Named array of theme info used by the API
	 */
	protected function format_theme( $theme ) {

		if ( ! ( $theme instanceof WP_Theme ) ) {
			$theme = wp_get_theme( $theme );
		}

		$fields = array(
			'name'        => 'Name',
			'theme_uri'   => 'ThemeURI',
			'description' => 'Description',
			'author'      => 'Author',
			'author_uri'  => 'AuthorURI',
			'tags'        => 'Tags',
			'version'     => 'Version',
		);

		$id              = $theme->get_stylesheet();
		$formatted_theme = array(
			'id'         => $id,
			'screenshot' => jetpack_photon_url( $theme->get_screenshot(), array(), 'network_path' ),
			'active'     => $id === $this->current_theme_id,
		);

		foreach ( $fields as $key => $field ) {
			$formatted_theme[ $key ] = $theme->get( $field );
		}

		$update_themes             = get_site_transient( 'update_themes' );
		$formatted_theme['update'] = ( isset( $update_themes->response[ $id ] ) ) ? $update_themes->response[ $id ] : null;

		$autoupdate                    = in_array( $id, Jetpack_Options::get_option( 'autoupdate_themes', array() ), true );
		$formatted_theme['autoupdate'] = $autoupdate;

		$autoupdate_translation                    = in_array( $id, Jetpack_Options::get_option( 'autoupdate_themes_translations', array() ), true );
		$formatted_theme['autoupdate_translation'] = $autoupdate || $autoupdate_translation || Jetpack_Options::get_option( 'autoupdate_translations', false );

		if ( isset( $this->log[ $id ] ) ) {
			$formatted_theme['log'] = $this->log[ $id ];
		}

		/**
		 * Filter the array of theme information that will be returned per theme by the Jetpack theme APIs.
		 *
		 * @module json-api
		 *
		 * @since 4.7.0
		 *
		 * @param array $formatted_theme The theme info array.
		 */
		return apply_filters( 'jetpack_format_theme_details', $formatted_theme );
	}

	/**
	 * Checks the query_args our collection endpoint was passed to ensure that it's in the proper bounds.
	 *
	 * @return bool|WP_Error a WP_Error object if the args are out of bounds, true if things are good.
	 */
	protected function check_query_args() {
		$args = $this->query_args();
		if ( $args['offset'] < 0 ) {
			return new WP_Error( 'invalid_offset', __( 'Offset must be greater than or equal to 0.', 'jetpack' ), 400 );
		}
		if ( $args['limit'] < 0 ) {
			return new WP_Error( 'invalid_limit', __( 'Limit must be greater than or equal to 0.', 'jetpack' ), 400 );
		}
		return true;
	}

	/**
	 * Format a list of themes for public display, using the supplied offset and limit args
	 *
	 * @uses   WPCOM_JSON_API_Endpoint::query_args()
	 * @return array         Public API theme objects
	 */
	protected function get_themes() {
		// ditch keys
		$themes = array_values( $this->themes );
		// do offset & limit - we've already returned a 400 error if they're bad numbers
		$args = $this->query_args();

		if ( isset( $args['offset'] ) ) {
			$themes = array_slice( $themes, (int) $args['offset'] );
		}
		if ( isset( $args['limit'] ) ) {
			$themes = array_slice( $themes, 0, (int) $args['limit'] );
		}

		$this->current_theme_id = wp_get_theme()->get_stylesheet();

		return array_map( array( $this, 'format_theme' ), $themes );
	}

}
