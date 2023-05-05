<?php

namespace WPForms\Helpers;

/**
 * Template related helper methods.
 *
 * @since 1.5.4
 */
class Templates {

	/**
	 * Return a list of paths to check for template locations
	 *
	 * @since 1.5.4
	 *
	 * @return array
	 */
	public static function get_theme_template_paths() {

		$template_dir = 'wpforms';

		$file_paths = [
			1   => \trailingslashit( \get_stylesheet_directory() ) . $template_dir,
			10  => \trailingslashit( \get_template_directory() ) . $template_dir,
			100 => \trailingslashit( \WPFORMS_PLUGIN_DIR ) . 'templates',
		];

		$file_paths = \apply_filters( 'wpforms_helpers_templates_get_theme_template_paths', $file_paths );

		// Sort the file paths based on priority.
		\ksort( $file_paths, SORT_NUMERIC );

		return \array_map( 'trailingslashit', $file_paths );
	}

	/**
	 * Locate a template and return the path for inclusion.
	 *
	 * @since 1.5.4
	 *
	 * @param string $template_name Template name.
	 *
	 * @return string
	 */
	public static function locate( $template_name ) {

		// Trim off any slashes from the template name.
		$template_name = \ltrim( $template_name, '/' );

		if ( empty( $template_name ) ) {
			return \apply_filters( 'wpforms_helpers_templates_locate', '', $template_name );
		}

		$located = '';

		// Try locating this template file by looping through the template paths.
		foreach ( self::get_theme_template_paths() as $template_path ) {
			if ( \file_exists( $template_path . $template_name ) ) {
				$located = $template_path . $template_name;
				break;
			}
		}

		return \apply_filters( 'wpforms_helpers_templates_locate', $located, $template_name );
	}

	/**
	 * Include a template.
	 * Use 'require' if $args are passed or 'load_template' if not.
	 *
	 * @since 1.5.4
	 *
	 * @param string $template_name Template name.
	 * @param array  $args          Arguments.
	 * @param bool   $extract       Extract arguments.
	 *
	 * @throws \RuntimeException If extract() tries to modify the scope.
	 */
	public static function include_html( $template_name, $args = [], $extract = false ) {

		$template_name .= '.php';

		// Allow 3rd party plugins to filter template file from their plugin.
		$located = \apply_filters( 'wpforms_helpers_templates_include_html_located', self::locate( $template_name ), $template_name, $args, $extract );
		$args    = \apply_filters( 'wpforms_helpers_templates_include_html_args', $args, $template_name, $extract );

		if ( empty( $located ) || ! \is_readable( $located ) ) {
			return;
		}

		// Load template WP way if no arguments were passed.
		if ( empty( $args ) ) {
			\load_template( $located, false );
			return;
		}

		$extract = \apply_filters( 'wpforms_helpers_templates_include_html_extract_args', $extract, $template_name, $args );

		if ( $extract && \is_array( $args ) ) {

			$created_vars_count = extract( $args, EXTR_SKIP ); // phpcs:ignore WordPress.PHP.DontExtract

			// Protecting existing scope from modification.
			if ( count( $args ) !== $created_vars_count ) {
				throw new \RuntimeException( 'Extraction failed: variable names are clashing with the existing ones.' );
			}
		}

		require $located;
	}

	/**
	 * Like self::include_html, but returns the HTML instead of including.
	 *
	 * @since 1.5.4
	 *
	 * @param string $template_name Template name.
	 * @param array  $args          Arguments.
	 * @param bool   $extract       Extract arguments.
	 *
	 * @return string
	 */
	public static function get_html( $template_name, $args = [], $extract = false ) {

		\ob_start();
		self::include_html( $template_name, $args, $extract );
		return \ob_get_clean();
	}

	/**
	 * Validate that a file path is safe and within the expected path(s).
	 *
	 * Author Scott Kingsley Clark, Pods Framework.
	 * Refactored to reduce cyclomatic complexity.
	 *
	 * @since 1.7.5.5
	 *
	 * @link https://github.com/pods-framework/pods/commit/ea53471e58e638dec06957edc38f9fa86607652c
	 *
	 * @param string            $path           The file path.
	 * @param null|array|string $paths_to_check The list of path types to check, defaults to just checking 'wpforms'.
	 *                                          Available: 'wpforms', 'plugins', 'theme',
	 *                                          or 'all' to check all supported paths.
	 *
	 * @return false|string False if the path was not allowed or did not exist, otherwise it returns the normalized path.
	 */
	public static function validate_safe_path( $path, $paths_to_check = null ) {

		static $available_checks;

		if ( ! $available_checks ) {
			$available_checks = [
				'wpforms' => realpath( WPFORMS_PLUGIN_DIR ),
				'plugins' => [
					realpath( WP_PLUGIN_DIR ),
					realpath( WPMU_PLUGIN_DIR ),
				],
				'theme'   => [
					realpath( get_stylesheet_directory() ),
					realpath( get_template_directory() ),
				],
			];

			$available_checks['plugins'] = array_unique( array_filter( $available_checks['plugins'] ) );
			$available_checks['theme']   = array_unique( array_filter( $available_checks['theme'] ) );
			$available_checks            = array_filter( $available_checks );
		}

		$paths_to_check = $paths_to_check === null ? [ 'wpforms' ] : $paths_to_check;
		$paths_to_check = $paths_to_check === 'all' ? array_keys( $available_checks ) : $paths_to_check;
		$paths_to_check = (array) $paths_to_check;

		if ( empty( $paths_to_check ) ) {
			return false;
		}

		$path = wp_normalize_path( trim( (string) $path ) );

		$match_count = 1;

		// Replace the ../ usage as many times as it may need to be replaced.
		while ( $match_count ) {
			$path = str_replace( '../', '', $path, $match_count );
		}

		$path = realpath( $path );

		foreach ( $paths_to_check as $check_type ) {
			if ( self::has_match( $path, $available_checks, $check_type ) ) {
				return $path;
			}
		}

		return false;
	}

	/**
	 * Whether path matches.
	 *
	 * @since 1.7.5.5
	 *
	 * @param string|bool $path             Path.
	 * @param array       $available_checks Available checks.
	 * @param string      $check_type       Check type.
	 *
	 * @return bool
	 */
	private static function has_match( $path, $available_checks, $check_type ) {

		if ( ! $path || ! isset( $available_checks[ $check_type ] ) ) {
			return false;
		}

		$check_type_paths = (array) $available_checks[ $check_type ];

		foreach ( $check_type_paths as $path_to_check ) {
			if ( 0 === strpos( $path, $path_to_check ) && file_exists( $path ) ) {
				return true;
			}
		}

		return false;
	}
}
