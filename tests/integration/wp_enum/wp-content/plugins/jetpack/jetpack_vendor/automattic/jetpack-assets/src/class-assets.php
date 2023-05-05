<?php
/**
 * Jetpack Assets package.
 *
 * @package  automattic/jetpack-assets
 */

namespace Automattic\Jetpack;

use Automattic\Jetpack\Assets\Semver;
use Automattic\Jetpack\Constants as Jetpack_Constants;
use InvalidArgumentException;

/**
 * Class Assets
 */
class Assets {
	/**
	 * Holds all the scripts handles that should be loaded in a deferred fashion.
	 *
	 * @var array
	 */
	private $defer_script_handles = array();

	/**
	 * The singleton instance of this class.
	 *
	 * @var Assets
	 */
	protected static $instance;

	/**
	 * The registered textdomain mappings.
	 *
	 * @var array `array( mapped_domain => array( string target_domain, string target_type, string semver, string path_prefix ) )`.
	 */
	private static $domain_map = array();

	/**
	 * Constructor.
	 *
	 * Static-only class, so nothing here.
	 */
	private function __construct() {}

	// ////////////////////
	// region Async script loading

	/**
	 * Get the singleton instance of the class.
	 *
	 * @return Assets
	 */
	public static function instance() {
		if ( ! isset( self::$instance ) ) {
			self::$instance = new Assets();
			self::$instance->init_hooks();
		}

		return self::$instance;
	}

	/**
	 * Initalize the hooks as needed.
	 */
	private function init_hooks() {
		/*
		 * Load some scripts asynchronously.
		 */
		add_filter( 'script_loader_tag', array( $this, 'script_add_async' ), 10, 2 );
	}

	/**
	 * A public method for adding the async script.
	 *
	 * @param string $script_handle Script handle.
	 */
	public static function add_async_script( $script_handle ) {
		$assets_instance                         = self::instance();
		$assets_instance->defer_script_handles[] = $script_handle;
	}

	/**
	 * Add an async attribute to scripts that can be loaded deferred.
	 * https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script
	 *
	 * @param string $tag    The <script> tag for the enqueued script.
	 * @param string $handle The script's registered handle.
	 */
	public function script_add_async( $tag, $handle ) {
		if ( empty( $this->defer_script_handles ) ) {
			return $tag;
		}

		if ( in_array( $handle, $this->defer_script_handles, true ) ) {
			// phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript
			return preg_replace( '/<script( [^>]*)? src=/i', '<script defer$1 src=', $tag );
		}

		return $tag;
	}

	/**
	 * A helper function that lets you enqueue scripts in an async fashion.
	 *
	 * @param string $handle        Name of the script. Should be unique.
	 * @param string $min_path      Minimized script path.
	 * @param string $non_min_path  Full Script path.
	 * @param array  $deps           Array of script dependencies.
	 * @param bool   $ver             The script version.
	 * @param bool   $in_footer       Should the script be included in the footer.
	 */
	public static function enqueue_async_script( $handle, $min_path, $non_min_path, $deps = array(), $ver = false, $in_footer = true ) {
		$assets_instance = self::instance();
		$assets_instance->add_async_script( $handle );
		wp_enqueue_script( $handle, self::get_file_url_for_environment( $min_path, $non_min_path ), $deps, $ver, $in_footer );
	}

	// endregion .

	// ////////////////////
	// region Utils

	/**
	 * Given a minified path, and a non-minified path, will return
	 * a minified or non-minified file URL based on whether SCRIPT_DEBUG is set and truthy.
	 *
	 * If $package_path is provided, then the minified or non-minified file URL will be generated
	 * relative to the root package directory.
	 *
	 * Both `$min_base` and `$non_min_base` can be either full URLs, or are expected to be relative to the
	 * root Jetpack directory.
	 *
	 * @param string $min_path     minified path.
	 * @param string $non_min_path non-minified path.
	 * @param string $package_path Optional. A full path to a file inside a package directory
	 *                             The URL will be relative to its directory. Default empty.
	 *                             Typically this is done by passing __FILE__ as the argument.
	 *
	 * @return string The URL to the file
	 * @since 1.0.3
	 * @since-jetpack 5.6.0
	 */
	public static function get_file_url_for_environment( $min_path, $non_min_path, $package_path = '' ) {
		$path = ( Jetpack_Constants::is_defined( 'SCRIPT_DEBUG' ) && Jetpack_Constants::get_constant( 'SCRIPT_DEBUG' ) )
			? $non_min_path
			: $min_path;

		/*
		 * If the path is actually a full URL, keep that.
		 * We look for a host value, since enqueues are sometimes without a scheme.
		 */
		$file_parts = wp_parse_url( $path );
		if ( ! empty( $file_parts['host'] ) ) {
			$url = $path;
		} else {
			$plugin_path = empty( $package_path ) ? Jetpack_Constants::get_constant( 'JETPACK__PLUGIN_FILE' ) : $package_path;

			$url = plugins_url( $path, $plugin_path );
		}

		/**
		 * Filters the URL for a file passed through the get_file_url_for_environment function.
		 *
		 * @since 1.0.3
		 *
		 * @package assets
		 *
		 * @param string $url The URL to the file.
		 * @param string $min_path The minified path.
		 * @param string $non_min_path The non-minified path.
		 */
		return apply_filters( 'jetpack_get_file_for_environment', $url, $min_path, $non_min_path );
	}

	/**
	 * Passes an array of URLs to wp_resource_hints.
	 *
	 * @since 1.5.0
	 *
	 * @param string|array $urls URLs to hint.
	 * @param string       $type One of the supported resource types: dns-prefetch (default), preconnect, prefetch, or prerender.
	 */
	public static function add_resource_hint( $urls, $type = 'dns-prefetch' ) {
		add_filter(
			'wp_resource_hints',
			function ( $hints, $resource_type ) use ( $urls, $type ) {
				if ( $resource_type === $type ) {
					// Type casting to array required since the function accepts a single string.
					foreach ( (array) $urls as $url ) {
						$hints[] = $url;
					}
				}
				return $hints;
			},
			10,
			2
		);
	}

	/**
	 * Serve a WordPress.com static resource via a randomized wp.com subdomain.
	 *
	 * @since 1.9.0
	 *
	 * @param string $url WordPress.com static resource URL.
	 *
	 * @return string $url
	 */
	public static function staticize_subdomain( $url ) {
		// Extract hostname from URL.
		$host = wp_parse_url( $url, PHP_URL_HOST );

		// Explode hostname on '.'.
		$exploded_host = explode( '.', $host );

		// Retrieve the name and TLD.
		if ( count( $exploded_host ) > 1 ) {
			$name = $exploded_host[ count( $exploded_host ) - 2 ];
			$tld  = $exploded_host[ count( $exploded_host ) - 1 ];
			// Rebuild domain excluding subdomains.
			$domain = $name . '.' . $tld;
		} else {
			$domain = $host;
		}
		// Array of Automattic domains.
		$domains_allowed = array( 'wordpress.com', 'wp.com' );

		// Return $url if not an Automattic domain.
		if ( ! in_array( $domain, $domains_allowed, true ) ) {
			return $url;
		}

		if ( \is_ssl() ) {
			return preg_replace( '|https?://[^/]++/|', 'https://s-ssl.wordpress.com/', $url );
		}

		/*
		 * Generate a random subdomain id by taking the modulus of the crc32 value of the URL.
		 * Valid values are 0, 1, and 2.
		 */
		$static_counter = abs( crc32( basename( $url ) ) % 3 );

		return preg_replace( '|://[^/]+?/|', "://s$static_counter.wp.com/", $url );
	}

	/**
	 * Resolve '.' and '..' components in a path or URL.
	 *
	 * @since 1.12.0
	 * @param string $path Path or URL.
	 * @return string Normalized path or URL.
	 */
	public static function normalize_path( $path ) {
		$parts = wp_parse_url( $path );
		if ( ! isset( $parts['path'] ) ) {
			return $path;
		}

		$ret  = '';
		$ret .= isset( $parts['scheme'] ) ? $parts['scheme'] . '://' : '';
		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			$ret .= isset( $parts['user'] ) ? $parts['user'] : '';
			$ret .= isset( $parts['pass'] ) ? ':' . $parts['pass'] : '';
			$ret .= '@';
		}
		$ret .= isset( $parts['host'] ) ? $parts['host'] : '';
		$ret .= isset( $parts['port'] ) ? ':' . $parts['port'] : '';

		$pp = explode( '/', $parts['path'] );
		if ( '' === $pp[0] ) {
			$ret .= '/';
			array_shift( $pp );
		}
		$i = 0;
		while ( $i < count( $pp ) ) { // phpcs:ignore Squiz.PHP.DisallowSizeFunctionsInLoops.Found
			if ( '' === $pp[ $i ] || '.' === $pp[ $i ] || 0 === $i && '..' === $pp[ $i ] ) {
				array_splice( $pp, $i, 1 );
			} elseif ( '..' === $pp[ $i ] ) {
				array_splice( $pp, --$i, 2 );
			} else {
				++$i;
			}
		}
		$ret .= join( '/', $pp );

		$ret .= isset( $parts['query'] ) ? '?' . $parts['query'] : '';
		$ret .= isset( $parts['fragment'] ) ? '#' . $parts['fragment'] : '';

		return $ret;
	}

	// endregion .

	// ////////////////////
	// region Webpack-built script registration

	/**
	 * Register a Webpack-built script.
	 *
	 * Our Webpack-built scripts tend to need a bunch of boilerplate:
	 *  - A call to `Assets::get_file_url_for_environment()` for possible debugging.
	 *  - A call to `wp_register_style()` for extracted CSS, possibly with detection of RTL.
	 *  - Loading of dependencies and version provided by `@wordpress/dependency-extraction-webpack-plugin`.
	 *  - Avoiding WPCom's broken minifier.
	 *
	 * This wrapper handles all of that.
	 *
	 * @since 1.12.0
	 * @param string $handle      Name of the script. Should be unique across both scripts and styles.
	 * @param string $path        Minimized script path.
	 * @param string $relative_to File that `$path` is relative to. Pass `__FILE__`.
	 * @param array  $options     Additional options:
	 *  - `asset_path`:       (string|null) `.asset.php` to load. Default is to base it on `$path`.
	 *  - `async`:            (bool) Set true to register the script as async, like `Assets::enqueue_async_script()`
	 *  - `css_dependencies`: (string[]) Additional style dependencies to queue.
	 *  - `css_path`:         (string|null) `.css` to load. Default is to base it on `$path`.
	 *  - `dependencies`:     (string[]) Additional script dependencies to queue.
	 *  - `enqueue`:          (bool) Set true to enqueue the script immediately.
	 *  - `in_footer`:        (bool) Set true to register script for the footer.
	 *  - `media`:            (string) Media for the css file. Default 'all'.
	 *  - `minify`:           (bool|null) Set true to pass `minify=true` in the query string, or `null` to suppress the normal `minify=false`.
	 *  - `nonmin_path`:      (string) Non-minified script path.
	 *  - `textdomain`:       (string) Text domain for the script. Required if the script depends on wp-i18n.
	 *  - `version`:          (string) Override the version from the `asset_path` file.
	 * @throws \InvalidArgumentException If arguments are invalid.
	 */
	public static function register_script( $handle, $path, $relative_to, array $options = array() ) {
		if ( substr( $path, -3 ) !== '.js' ) {
			throw new \InvalidArgumentException( '$path must end in ".js"' );
		}

		$dir      = dirname( $relative_to );
		$base     = substr( $path, 0, -3 );
		$options += array(
			'asset_path'       => "$base.asset.php",
			'async'            => false,
			'css_dependencies' => array(),
			'css_path'         => "$base.css",
			'dependencies'     => array(),
			'enqueue'          => false,
			'in_footer'        => false,
			'media'            => 'all',
			'minify'           => false,
			'textdomain'       => null,
		);

		if ( $options['css_path'] && substr( $options['css_path'], -4 ) !== '.css' ) {
			throw new \InvalidArgumentException( '$options[\'css_path\'] must end in ".css"' );
		}

		if ( isset( $options['nonmin_path'] ) ) {
			$url = self::get_file_url_for_environment( $path, $options['nonmin_path'], $relative_to );
		} else {
			$url = plugins_url( $path, $relative_to );
		}
		$url = self::normalize_path( $url );
		if ( null !== $options['minify'] ) {
			$url = add_query_arg( 'minify', $options['minify'] ? 'true' : 'false', $url );
		}

		if ( $options['asset_path'] && file_exists( "$dir/{$options['asset_path']}" ) ) {
			$asset                       = require "$dir/{$options['asset_path']}"; // phpcs:ignore WordPressVIPMinimum.Files.IncludingFile.NotAbsolutePath
			$options['dependencies']     = array_merge( $asset['dependencies'], $options['dependencies'] );
			$options['css_dependencies'] = array_merge(
				array_filter(
					$asset['dependencies'],
					function ( $d ) {
						return wp_style_is( $d, 'registered' );
					}
				),
				$options['css_dependencies']
			);
			$ver                         = isset( $options['version'] ) ? $options['version'] : $asset['version'];
		} else {
			$ver = isset( $options['version'] ) ? $options['version'] : filemtime( "$dir/$path" );
		}

		wp_register_script( $handle, $url, $options['dependencies'], $ver, $options['in_footer'] );
		if ( $options['async'] ) {
			self::instance()->add_async_script( $handle );
		}
		if ( $options['textdomain'] ) {
			// phpcs:ignore Jetpack.Functions.I18n.DomainNotLiteral
			wp_set_script_translations( $handle, $options['textdomain'] );
		} elseif ( in_array( 'wp-i18n', $options['dependencies'], true ) ) {
			_doing_it_wrong(
				__METHOD__,
				/* translators: %s is the script handle. */
				esc_html( sprintf( __( 'Script "%s" depends on wp-i18n but does not specify "textdomain"', 'jetpack-assets' ), $handle ) ),
				''
			);
		}

		if ( $options['css_path'] && file_exists( "$dir/{$options['css_path']}" ) ) {
			$csspath = $options['css_path'];
			if ( is_rtl() ) {
				$rtlcsspath = substr( $csspath, 0, -4 ) . '.rtl.css';
				if ( file_exists( "$dir/$rtlcsspath" ) ) {
					$csspath = $rtlcsspath;
				}
			}

			$url = self::normalize_path( plugins_url( $csspath, $relative_to ) );
			if ( null !== $options['minify'] ) {
				$url = add_query_arg( 'minify', $options['minify'] ? 'true' : 'false', $url );
			}
			wp_register_style( $handle, $url, $options['css_dependencies'], $ver, $options['media'] );
			wp_script_add_data( $handle, 'Jetpack::Assets::hascss', true );
		} else {
			wp_script_add_data( $handle, 'Jetpack::Assets::hascss', false );
		}

		if ( $options['enqueue'] ) {
			self::enqueue_script( $handle );
		}
	}

	/**
	 * Enqueue a script registered with `Assets::register_script`.
	 *
	 * @since 1.12.0
	 * @param string $handle       Name of the script. Should be unique across both scripts and styles.
	 */
	public static function enqueue_script( $handle ) {
		wp_enqueue_script( $handle );
		if ( wp_scripts()->get_data( $handle, 'Jetpack::Assets::hascss' ) ) {
			wp_enqueue_style( $handle );
		}
	}

	/**
	 * 'wp_default_scripts' action handler.
	 *
	 * This registers the `wp-jp-i18n-loader` script for use by Webpack bundles built with
	 * `@automattic/i18n-loader-webpack-plugin`.
	 *
	 * @since 1.14.0
	 * @param \WP_Scripts $wp_scripts WP_Scripts instance.
	 */
	public static function wp_default_scripts_hook( $wp_scripts ) {
		$data = array(
			'baseUrl'     => false,
			'locale'      => determine_locale(),
			'domainMap'   => array(),
			'domainPaths' => array(),
		);

		$lang_dir    = Jetpack_Constants::get_constant( 'WP_LANG_DIR' );
		$content_dir = Jetpack_Constants::get_constant( 'WP_CONTENT_DIR' );
		$abspath     = Jetpack_Constants::get_constant( 'ABSPATH' );

		if ( strpos( $lang_dir, $content_dir ) === 0 ) {
			$data['baseUrl'] = content_url( substr( trailingslashit( $lang_dir ), strlen( trailingslashit( $content_dir ) ) ) );
		} elseif ( strpos( $lang_dir, $abspath ) === 0 ) {
			$data['baseUrl'] = site_url( substr( trailingslashit( $lang_dir ), strlen( untrailingslashit( $abspath ) ) ) );
		}

		foreach ( self::$domain_map as $from => list( $to, $type, , $path ) ) {
			$data['domainMap'][ $from ] = ( 'core' === $type ? '' : "{$type}/" ) . $to;
			if ( '' !== $path ) {
				$data['domainPaths'][ $from ] = trailingslashit( $path );
			}
		}

		/**
		 * Filters the i18n state data for use by Webpack bundles built with
		 * `@automattic/i18n-loader-webpack-plugin`.
		 *
		 * @since 1.14.0
		 * @package assets
		 * @param array $data The state data to generate. Expected fields are:
		 *  - `baseUrl`: (string|false) The URL to the languages directory. False if no URL could be determined.
		 *  - `locale`: (string) The locale for the page.
		 *  - `domainMap`: (string[]) A mapping from Composer package textdomains to the corresponding
		 *    `plugins/textdomain` or `themes/textdomain` (or core `textdomain`, but that's unlikely).
		 *  - `domainPaths`: (string[]) A mapping from Composer package textdomains to the corresponding package
		 *     paths.
		 */
		$data = apply_filters( 'jetpack_i18n_state', $data );

		// Can't use self::register_script(), this action is called too early.
		if ( file_exists( __DIR__ . '/../build/i18n-loader.asset.php' ) ) {
			$path  = '../build/i18n-loader.js';
			$asset = require __DIR__ . '/../build/i18n-loader.asset.php';
		} else {
			$path  = 'js/i18n-loader.js';
			$asset = array(
				'dependencies' => array( 'wp-i18n' ),
				'version'      => filemtime( __DIR__ . "/$path" ),
			);
		}
		$url = self::normalize_path( plugins_url( $path, __FILE__ ) );
		$url = add_query_arg( 'minify', 'true', $url );
		$wp_scripts->add( 'wp-jp-i18n-loader', $url, $asset['dependencies'], $asset['version'] );
		if ( ! is_array( $data ) ||
			! isset( $data['baseUrl'] ) || ! ( is_string( $data['baseUrl'] ) || false === $data['baseUrl'] ) ||
			! isset( $data['locale'] ) || ! is_string( $data['locale'] ) ||
			! isset( $data['domainMap'] ) || ! is_array( $data['domainMap'] ) ||
			! isset( $data['domainPaths'] ) || ! is_array( $data['domainPaths'] )
		) {
			$wp_scripts->add_inline_script( 'wp-jp-i18n-loader', 'console.warn( "I18n state deleted by jetpack_i18n_state hook" );' );
		} elseif ( ! $data['baseUrl'] ) {
			$wp_scripts->add_inline_script( 'wp-jp-i18n-loader', 'console.warn( "Failed to determine languages base URL. Is WP_LANG_DIR in the WordPress root?" );' );
		} else {
			$data['domainMap']   = (object) $data['domainMap']; // Ensure it becomes a json object.
			$data['domainPaths'] = (object) $data['domainPaths']; // Ensure it becomes a json object.
			$wp_scripts->add_inline_script( 'wp-jp-i18n-loader', 'wp.jpI18nLoader.state = ' . wp_json_encode( $data, JSON_UNESCAPED_SLASHES ) . ';' );
		}

		// Deprecated state module: Depend on wp-i18n to ensure global `wp` exists and because anything needing this will need that too.
		$wp_scripts->add( 'wp-jp-i18n-state', null, array( 'wp-deprecated', 'wp-jp-i18n-loader' ) );
		$wp_scripts->add_inline_script( 'wp-jp-i18n-state', 'wp.deprecated( "wp-jp-i18n-state", { alternative: "wp-jp-i18n-loader" } );' );
		$wp_scripts->add_inline_script( 'wp-jp-i18n-state', 'wp.jpI18nState = wp.jpI18nLoader.state;' );
	}

	// endregion .

	// ////////////////////
	// region Textdomain aliasing

	/**
	 * Register a textdomain alias.
	 *
	 * Composer packages included in plugins will likely not use the textdomain of the plugin, while
	 * WordPress's i18n infrastructure will include the translations in the plugin's domain. This
	 * allows for mapping the package's domain to the plugin's.
	 *
	 * Since multiple plugins may use the same package, we include the package's version here so
	 * as to choose the most recent translations (which are most likely to match the package
	 * selected by jetpack-autoloader).
	 *
	 * @since 1.15.0
	 * @param string $from Domain to alias.
	 * @param string $to Domain to alias it to.
	 * @param string $totype What is the target of the alias: 'plugins', 'themes', or 'core'.
	 * @param string $ver Version of the `$from` domain.
	 * @param string $path Path to prepend when lazy-loading from JavaScript.
	 * @throws InvalidArgumentException If arguments are invalid.
	 */
	public static function alias_textdomain( $from, $to, $totype, $ver, $path = '' ) {
		if ( ! in_array( $totype, array( 'plugins', 'themes', 'core' ), true ) ) {
			throw new InvalidArgumentException( 'Type must be "plugins", "themes", or "core"' );
		}

		if (
			did_action( 'wp_default_scripts' ) &&
			// Don't complain during plugin activation.
			! defined( 'WP_SANDBOX_SCRAPING' )
		) {
			_doing_it_wrong(
				__METHOD__,
				sprintf(
					/* translators: 1: wp_default_scripts. 2: Name of the domain being aliased. */
					esc_html__( 'Textdomain aliases should be registered before the %1$s hook. This notice was triggered by the %2$s domain.', 'jetpack-assets' ),
					'<code>wp_default_scripts</code>',
					'<code>' . esc_html( $from ) . '</code>'
				),
				''
			);
		}

		if ( empty( self::$domain_map[ $from ] ) ) {
			self::init_domain_map_hooks( $from, array() === self::$domain_map );
			self::$domain_map[ $from ] = array( $to, $totype, $ver, $path );
		} elseif ( Semver::compare( $ver, self::$domain_map[ $from ][2] ) > 0 ) {
			self::$domain_map[ $from ] = array( $to, $totype, $ver, $path );
		}
	}

	/**
	 * Register textdomain aliases from a mapping file.
	 *
	 * The mapping file is simply a PHP file that returns an array
	 * with the following properties:
	 *  - 'domain': String, `$to`
	 *  - 'type': String, `$totype`
	 *  - 'packages': Array, mapping `$from` to `array( 'path' => $path, 'ver' => $ver )` (or to the string `$ver` for back compat).
	 *
	 * @since 1.15.0
	 * @param string $file Mapping file.
	 */
	public static function alias_textdomains_from_file( $file ) {
		$data = require $file;
		foreach ( $data['packages'] as $from => $fromdata ) {
			if ( ! is_array( $fromdata ) ) {
				$fromdata = array(
					'path' => '',
					'ver'  => $fromdata,
				);
			}
			self::alias_textdomain( $from, $data['domain'], $data['type'], $fromdata['ver'], $fromdata['path'] );
		}
	}

	/**
	 * Register the hooks for textdomain aliasing.
	 *
	 * @param string $domain Domain to alias.
	 * @param bool   $firstcall If this is the first call.
	 */
	private static function init_domain_map_hooks( $domain, $firstcall ) {
		// If WordPress's plugin API is available already, use it. If not,
		// drop data into `$wp_filter` for `WP_Hook::build_preinitialized_hooks()`.
		if ( function_exists( 'add_filter' ) ) {
			$add_filter = 'add_filter';
		} else {
			$add_filter = function ( $hook_name, $callback, $priority = 10, $accepted_args = 1 ) {
				global $wp_filter;
				// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
				$wp_filter[ $hook_name ][ $priority ][] = array(
					'accepted_args' => $accepted_args,
					'function'      => $callback,
				);
			};
		}

		$add_filter( "gettext_{$domain}", array( self::class, 'filter_gettext' ), 10, 3 );
		$add_filter( "ngettext_{$domain}", array( self::class, 'filter_ngettext' ), 10, 5 );
		$add_filter( "gettext_with_context_{$domain}", array( self::class, 'filter_gettext_with_context' ), 10, 4 );
		$add_filter( "ngettext_with_context_{$domain}", array( self::class, 'filter_ngettext_with_context' ), 10, 6 );
		if ( $firstcall ) {
			$add_filter( 'load_script_translation_file', array( self::class, 'filter_load_script_translation_file' ), 10, 3 );
		}
	}

	/**
	 * Filter for `gettext`.
	 *
	 * @since 1.15.0
	 * @param string $translation Translated text.
	 * @param string $text Text to translate.
	 * @param string $domain Text domain.
	 * @return string Translated text.
	 */
	public static function filter_gettext( $translation, $text, $domain ) {
		if ( $translation === $text ) {
			// phpcs:ignore WordPress.WP.I18n
			$newtext = __( $text, self::$domain_map[ $domain ][0] );
			if ( $newtext !== $text ) {
				return $newtext;
			}
		}
		return $translation;
	}

	/**
	 * Filter for `ngettext`.
	 *
	 * @since 1.15.0
	 * @param string $translation Translated text.
	 * @param string $single The text to be used if the number is singular.
	 * @param string $plural The text to be used if the number is plural.
	 * @param string $number The number to compare against to use either the singular or plural form.
	 * @param string $domain Text domain.
	 * @return string Translated text.
	 */
	public static function filter_ngettext( $translation, $single, $plural, $number, $domain ) {
		if ( $translation === $single || $translation === $plural ) {
			// phpcs:ignore WordPress.WP.I18n
			$translation = _n( $single, $plural, $number, self::$domain_map[ $domain ][0] );
		}
		return $translation;
	}

	/**
	 * Filter for `gettext_with_context`.
	 *
	 * @since 1.15.0
	 * @param string $translation Translated text.
	 * @param string $text Text to translate.
	 * @param string $context Context information for the translators.
	 * @param string $domain Text domain.
	 * @return string Translated text.
	 */
	public static function filter_gettext_with_context( $translation, $text, $context, $domain ) {
		if ( $translation === $text ) {
			// phpcs:ignore WordPress.WP.I18n
			$translation = _x( $text, $context, self::$domain_map[ $domain ][0] );
		}
		return $translation;
	}

	/**
	 * Filter for `ngettext_with_context`.
	 *
	 * @since 1.15.0
	 * @param string $translation Translated text.
	 * @param string $single The text to be used if the number is singular.
	 * @param string $plural The text to be used if the number is plural.
	 * @param string $number The number to compare against to use either the singular or plural form.
	 * @param string $context Context information for the translators.
	 * @param string $domain Text domain.
	 * @return string Translated text.
	 */
	public static function filter_ngettext_with_context( $translation, $single, $plural, $number, $context, $domain ) {
		if ( $translation === $single || $translation === $plural ) {
			// phpcs:ignore WordPress.WP.I18n
			$translation = _nx( $single, $plural, $number, $context, self::$domain_map[ $domain ][0] );
		}
		return $translation;
	}

	/**
	 * Filter for `load_script_translation_file`.
	 *
	 * @since 1.15.0
	 * @param string|false $file Path to the translation file to load. False if there isn't one.
	 * @param string       $handle Name of the script to register a translation domain to.
	 * @param string       $domain The text domain.
	 */
	public static function filter_load_script_translation_file( $file, $handle, $domain ) {
		if ( false !== $file && isset( self::$domain_map[ $domain ] ) && ! is_readable( $file ) ) {
			// Determine the part of the filename after the domain.
			$suffix = basename( $file );
			$l      = strlen( $domain );
			if ( substr( $suffix, 0, $l ) !== $domain || '-' !== $suffix[ $l ] ) {
				return $file;
			}
			$suffix   = substr( $suffix, $l );
			$lang_dir = Jetpack_Constants::get_constant( 'WP_LANG_DIR' );

			// Look for replacement files.
			list( $newdomain, $type ) = self::$domain_map[ $domain ];
			$newfile                  = $lang_dir . ( 'core' === $type ? '/' : "/{$type}/" ) . $newdomain . $suffix;
			if ( is_readable( $newfile ) ) {
				return $newfile;
			}
		}
		return $file;
	}

	// endregion .

}

// Enable section folding in vim:
// vim: foldmarker=//\ region,//\ endregion foldmethod=marker
// .
