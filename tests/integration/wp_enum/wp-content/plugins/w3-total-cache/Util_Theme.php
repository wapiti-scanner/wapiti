<?php
namespace W3TC;

class Util_Theme {
	static public function get( $themename ) {
		$wp_themes = Util_Theme::get_themes();


		if ( is_array( $wp_themes ) && array_key_exists( $themename, $wp_themes ) )
			return $wp_themes[ $themename ];
		return array();
	}
	static public function get_current_theme_name() {
		return wp_get_theme()->get( 'Name' );
	}

	static public function get_current_theme() {
		return wp_get_theme();
	}

	static public function get_themes() {
		global $wp_themes;
		if ( isset( $wp_themes ) )
			return $wp_themes;

		$themes = wp_get_themes();
		$wp_themes = array();

		foreach ( $themes as $theme ) {
			$name = $theme->get( 'Name' );
			if ( isset( $wp_themes[$name] ) )
				$wp_themes[$name . '/' . $theme->get_stylesheet()] = $theme;
			else
				$wp_themes[$name] = $theme;
		}

		return $wp_themes;
	}

	/**
	 * Returns theme key
	 *
	 * @param string  $theme_root
	 * @param string  $template
	 * @param string  $stylesheet
	 * @return string
	 */
	static public function get_theme_key( $theme_root, $template, $stylesheet ) {
		$theme_path = ltrim( str_replace( WP_CONTENT_DIR, '',
				Util_Environment::normalize_path( $theme_root ) ), '/' );

		return substr( md5( $theme_path . $template . $stylesheet ), 0, 5 );
	}

	/**
	 * Returns themes array
	 *
	 * @return array
	 */
	static public function get_themes_by_key() {
		$themes = array();
		$wp_themes = Util_Theme::get_themes();

		foreach ( $wp_themes as $wp_theme ) {
			$theme_key = Util_Theme::get_theme_key( $wp_theme['Theme Root'], $wp_theme['Template'], $wp_theme['Stylesheet'] );
			$themes[$theme_key] = $wp_theme['Name'];
		}

		return $themes;
	}

	/**
	 * Returns minify groups
	 *
	 * @param string  $theme_name
	 * @return array
	 */
	static public function get_theme_templates( $theme_name ) {
		$groups = array(
			'default' => __( 'All Templates', 'w3-total-cache' )
		);

		$templates = Util_Theme::get_theme_files( $theme_name );

		foreach ( $templates as $template ) {
			$basename = basename( $template, '.php' );

			$groups[$basename] = ucfirst( $basename );
		}

		return $groups;
	}


	/**
	 * Returns array of theme groups
	 *
	 * @param string  $theme_name
	 * @return array
	 */
	static public function get_theme_files( $theme_name ) {
		$patterns = array(
			'404',
			'search',
			'taxonomy((-|_).*)?',
			'front-page',
			'home',
			'index',
			'(image|video|text|audio|application).*',
			'attachment',
			'single((-|_).*)?',
			'page((-|_).*)?',
			'category((-|_).*)?',
			'tag((-|_).*)?',
			'author((-|_).*)?',
			'date',
			'archive',
			'comments-popup',
			'paged'
		);

		$templates = array();
		$theme = Util_Theme::get( $theme_name );

		if ( $theme && isset( $theme['Template Files'] ) ) {
			$template_files = (array) $theme['Template Files'];

			foreach ( $template_files as $template_file ) {
				/**
				 * Check file name
				 */
				$template = basename( $template_file, '.php' );

				foreach ( $patterns as $pattern ) {
					$regexp = '~^' . $pattern . '$~';

					if ( preg_match( $regexp, $template ) ) {
						$templates[] = $template_file;
						continue 2;
					}
				}

				/**
				 * Check get_header function call
				 */
				$template_content = @file_get_contents( $template_file );

				if ( $template_content && preg_match( '~\s*get_header[0-9_]*\s*\(~', $template_content ) ) {
					$templates[] = $template_file;
				}
			}

			sort( $templates );
			reset( $templates );
		}

		return $templates;
	}


}
