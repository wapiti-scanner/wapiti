<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Module Name: Asset CDN
 * Module Description: Jetpack’s Site Accelerator loads your site faster by optimizing your images and serving your images and static files from our global network of servers.
 * Sort Order: 26
 * Recommendation Order: 1
 * First Introduced: 6.6
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Photos and Videos, Appearance, Recommended
 * Feature: Recommended, Appearance
 * Additional Search Queries: site accelerator, accelerate, static, assets, javascript, css, files, performance, cdn, bandwidth, content delivery network, pagespeed, combine js, optimize css
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;

$GLOBALS['concatenate_scripts'] = false; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited

Assets::add_resource_hint( '//c0.wp.com', 'dns-prefetch' );

/**
 * Asset CDN module main class file.
 */
class Jetpack_Photon_Static_Assets_CDN {
	const CDN = 'https://c0.wp.com/';

	/**
	 * Sets up action handlers needed for Jetpack CDN.
	 */
	public static function go() {
		add_action( 'wp_print_scripts', array( __CLASS__, 'cdnize_assets' ) );
		add_action( 'wp_print_styles', array( __CLASS__, 'cdnize_assets' ) );
		add_action( 'admin_print_scripts', array( __CLASS__, 'cdnize_assets' ) );
		add_action( 'admin_print_styles', array( __CLASS__, 'cdnize_assets' ) );
		add_action( 'wp_footer', array( __CLASS__, 'cdnize_assets' ) );
		add_filter( 'load_script_textdomain_relative_path', array( __CLASS__, 'fix_script_relative_path' ), 10, 2 );
		add_filter( 'load_script_translation_file', array( __CLASS__, 'fix_local_script_translation_path' ), 10, 3 );
	}

	/**
	 * Sets up CDN URLs for assets that are enqueued by the WordPress Core.
	 */
	public static function cdnize_assets() {
		global $wp_scripts, $wp_styles, $wp_version;

		/*
		 * Short-circuit if AMP since not relevant as custom JS is not allowed and CSS is inlined.
		 * Note that it is not suitable to use the jetpack_force_disable_site_accelerator filter for this
		 * because it will be applied before the wp action, which is the point at which the queried object
		 * is available and we know whether the response will be AMP or not. This is particularly important
		 * for AMP-first (native AMP) pages where there are no AMP-specific URLs.
		 */
		if ( class_exists( Jetpack_AMP_Support::class ) && Jetpack_AMP_Support::is_amp_request() ) {
			return;
		}

		/**
		 * Filters Jetpack CDN's Core version number and locale. Can be used to override the values
		 * that Jetpack uses to retrieve assets. Expects the values to be returned in an array.
		 *
		 * @module photon-cdn
		 *
		 * @since 6.6.0
		 *
		 * @param array $values array( $version  = core assets version, i.e. 4.9.8, $locale = desired locale )
		 */
		list( $version, $locale ) = apply_filters( // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
			'jetpack_cdn_core_version_and_locale',
			array( $wp_version, get_locale() )
		);

		if ( self::is_public_version( $version ) ) {
			$site_url = trailingslashit( site_url() );
			foreach ( $wp_scripts->registered as $handle => $thing ) {
				if ( wp_startswith( $thing->src, self::CDN ) ) {
					continue;
				}
				if ( ! is_string( $thing->src ) ) {
					continue;
				}
				$src = ltrim( str_replace( $site_url, '', $thing->src ), '/' );
				if ( self::is_js_or_css_file( $src ) && in_array( substr( $src, 0, 9 ), array( 'wp-admin/', 'wp-includ' ), true ) ) {
					$wp_scripts->registered[ $handle ]->src = sprintf( self::CDN . 'c/%1$s/%2$s', $version, $src );
					$wp_scripts->registered[ $handle ]->ver = null;
				}
			}
			foreach ( $wp_styles->registered as $handle => $thing ) {
				if ( wp_startswith( $thing->src, self::CDN ) ) {
					continue;
				}
				if ( ! is_string( $thing->src ) ) {
					continue;
				}
				$src = ltrim( str_replace( $site_url, '', $thing->src ), '/' );
				if ( self::is_js_or_css_file( $src ) && in_array( substr( $src, 0, 9 ), array( 'wp-admin/', 'wp-includ' ), true ) ) {
					$wp_styles->registered[ $handle ]->src = sprintf( self::CDN . 'c/%1$s/%2$s', $version, $src );
					$wp_styles->registered[ $handle ]->ver = null;
				}
			}
		}

		self::cdnize_plugin_assets( 'jetpack', JETPACK__VERSION );
		if ( class_exists( 'WooCommerce' ) ) {
			self::cdnize_plugin_assets( 'woocommerce', WC_VERSION );
		}
	}

	/**
	 * Ensure use of the correct relative path when determining the JavaScript file names.
	 *
	 * @param string $relative The relative path of the script. False if it could not be determined.
	 * @param string $src      The full source url of the script.
	 * @return string The expected relative path for the CDN-ed URL.
	 */
	public static function fix_script_relative_path( $relative, $src ) {

		// Note relevant in AMP responses. See note above.
		if ( class_exists( Jetpack_AMP_Support::class ) && Jetpack_AMP_Support::is_amp_request() ) {
			return $relative;
		}

		$strpos = strpos( $src, '/wp-includes/' );

		// We only treat URLs that have wp-includes in them. Cases like language textdomains
		// can also use this filter, they don't need to be touched because they are local paths.
		if ( false !== $strpos ) {
			return substr( $src, 1 + $strpos );
		}

		// Get the local path from a URL which was CDN'ed by cdnize_plugin_assets().
		if ( preg_match( '#^' . preg_quote( self::CDN, '#' ) . 'p/[^/]+/[^/]+/(.*)$#', $src, $m ) ) {
			return $m[1];
		}

		return $relative;
	}

	/**
	 * Ensure use of the correct local path when loading the JavaScript translation file for a CDN'ed asset.
	 *
	 * @param string|false $file   Path to the translation file to load. False if there isn't one.
	 * @param string       $handle The script handle.
	 * @param string       $domain The text domain.
	 *
	 * @return string The transformed local languages path.
	 */
	public static function fix_local_script_translation_path( $file, $handle, $domain ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		global $wp_scripts;

		// This is a rewritten plugin URL, so load the language file from the plugins path.
		if ( $file && isset( $wp_scripts->registered[ $handle ] ) && wp_startswith( $wp_scripts->registered[ $handle ]->src, self::CDN . 'p' ) ) {
			return WP_LANG_DIR . '/plugins/' . basename( $file );
		}

		return $file;
	}

	/**
	 * Sets up CDN URLs for supported plugin assets.
	 *
	 * @param String $plugin_slug plugin slug string.
	 * @param String $current_version plugin version string.
	 * @return null|bool
	 */
	public static function cdnize_plugin_assets( $plugin_slug, $current_version ) {
		global $wp_scripts, $wp_styles;

		/**
		 * Filters Jetpack CDN's plugin slug and version number. Can be used to override the values
		 * that Jetpack uses to retrieve assets. For example, when testing a development version of Jetpack
		 * the assets are not yet published, so you may need to override the version value to either
		 * trunk, or the latest available version. Expects the values to be returned in an array.
		 *
		 * @module photon-cdn
		 *
		 * @since 6.6.0
		 *
		 * @param array $values array( $slug = the plugin repository slug, i.e. jetpack, $version = the plugin version, i.e. 6.6 )
		 */
		list( $plugin_slug, $current_version ) = apply_filters(
			'jetpack_cdn_plugin_slug_and_version',
			array( $plugin_slug, $current_version )
		);

		$assets               = self::get_plugin_assets( $plugin_slug, $current_version );
		$plugin_directory_url = plugins_url() . '/' . $plugin_slug . '/';

		if ( is_wp_error( $assets ) || ! is_array( $assets ) ) {
			return false;
		}

		foreach ( $wp_scripts->registered as $handle => $thing ) {
			if ( wp_startswith( $thing->src, self::CDN ) ) {
				continue;
			}
			if ( wp_startswith( $thing->src, $plugin_directory_url ) ) {
				$local_path = substr( $thing->src, strlen( $plugin_directory_url ) );
				if ( in_array( $local_path, $assets, true ) ) {
					$wp_scripts->registered[ $handle ]->src = sprintf( self::CDN . 'p/%1$s/%2$s/%3$s', $plugin_slug, $current_version, $local_path );
					$wp_scripts->registered[ $handle ]->ver = null;
				}
			}
		}
		foreach ( $wp_styles->registered as $handle => $thing ) {
			if ( wp_startswith( $thing->src, self::CDN ) ) {
				continue;
			}
			if ( wp_startswith( $thing->src, $plugin_directory_url ) ) {
				$local_path = substr( $thing->src, strlen( $plugin_directory_url ) );
				if ( in_array( $local_path, $assets, true ) ) {
					$wp_styles->registered[ $handle ]->src = sprintf( self::CDN . 'p/%1$s/%2$s/%3$s', $plugin_slug, $current_version, $local_path );
					$wp_styles->registered[ $handle ]->ver = null;
				}
			}
		}
	}

	/**
	 * Returns cdn-able assets for a given plugin.
	 *
	 * @param string $plugin plugin slug string.
	 * @param string $version plugin version number string.
	 * @return array|bool Will return false if not a public version.
	 */
	public static function get_plugin_assets( $plugin, $version ) {
		if ( 'jetpack' === $plugin && JETPACK__VERSION === $version ) {
			if ( ! self::is_public_version( $version ) ) {
				return false;
			}

			$assets = array(); // The variable will be redefined in the included file.

			include JETPACK__PLUGIN_DIR . 'modules/photon-cdn/jetpack-manifest.php';
			return $assets;
		}

		/**
		 * Used for other plugins to provide their bundled assets via filter to
		 * prevent the need of storing them in an option or an external api request
		 * to w.org.
		 *
		 * @module photon-cdn
		 *
		 * @since 6.6.0
		 *
		 * @param array $assets The assets array for the plugin.
		 * @param string $version The version of the plugin being requested.
		 */
		$assets = apply_filters( "jetpack_cdn_plugin_assets-{$plugin}", null, $version ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores
		if ( is_array( $assets ) ) {
			return $assets;
		}

		if ( ! self::is_public_version( $version ) ) {
			return false;
		}

		$cache = Jetpack_Options::get_option( 'static_asset_cdn_files', array() );
		if ( isset( $cache[ $plugin ][ $version ] ) ) {
			if ( is_array( $cache[ $plugin ][ $version ] ) ) {
				return $cache[ $plugin ][ $version ];
			}
			if ( is_numeric( $cache[ $plugin ][ $version ] ) ) {
				// Cache an empty result for up to 24h.
				if ( (int) $cache[ $plugin ][ $version ] + DAY_IN_SECONDS > time() ) {
					return array();
				}
			}
		}

		$url = sprintf( 'http://downloads.wordpress.org/plugin-checksums/%s/%s.json', $plugin, $version );

		if ( wp_http_supports( array( 'ssl' ) ) ) {
			$url = set_url_scheme( $url, 'https' );
		}

		$response = wp_remote_get( $url );

		$body = trim( wp_remote_retrieve_body( $response ) );
		$body = json_decode( $body, true );

		$return = time();
		if ( is_array( $body ) ) {
			$return = array_filter( array_keys( $body['files'] ), array( __CLASS__, 'is_js_or_css_file' ) );
		}

		$cache[ $plugin ]             = array();
		$cache[ $plugin ][ $version ] = $return;
		Jetpack_Options::update_option( 'static_asset_cdn_files', $cache, true );

		return $return;
	}

	/**
	 * Checks a path whether it is a JS or CSS file.
	 *
	 * @param String $path file path.
	 * @return Boolean whether the file is a JS or CSS.
	 */
	public static function is_js_or_css_file( $path ) {
		return ( false === strpos( $path, '?' ) ) && in_array( substr( $path, -3 ), array( 'css', '.js' ), true );
	}

	/**
	 * Checks whether the version string indicates a production version.
	 *
	 * @param String  $version the version string.
	 * @param Boolean $include_beta_and_rc whether to count beta and RC versions as production.
	 * @return Boolean
	 */
	public static function is_public_version( $version, $include_beta_and_rc = false ) {
		if ( preg_match( '/^\d+(\.\d+)+$/', $version ) ) {
			/** Example matches: `1`, `1.2`, `1.2.3`. */
			return true;
		} elseif ( $include_beta_and_rc && preg_match( '/^\d+(\.\d+)+(-(beta|rc|pressable)\d?)$/i', $version ) ) {
			/** Example matches: `1.2.3`, `1.2.3-beta`, `1.2.3-pressable`, `1.2.3-beta1`, `1.2.3-rc`, `1.2.3-rc2`. */
			return true;
		}
		// Unrecognized version.
		return false;
	}
}
/**
 * Allow plugins to short-circuit the Asset CDN, even when the module is on.
 *
 * @module photon-cdn
 *
 * @since 6.7.0
 *
 * @param false bool Should the Asset CDN be blocked? False by default.
 */
if ( true !== apply_filters( 'jetpack_force_disable_site_accelerator', false ) ) {
	Jetpack_Photon_Static_Assets_CDN::go();
}
