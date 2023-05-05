<?php
namespace W3TC;





/**
 * class Minify_Environment
 */
class Minify_Environment {
	public function __construct() {
		add_filter( 'w3tc_browsercache_rules_section',
			array( $this, 'w3tc_browsercache_rules_section' ),
			10, 3 );
	}

	/**
	 * Fixes environment in each wp-admin request
	 *
	 * @param Config  $config
	 * @param bool    $force_all_checks
	 *
	 * @throws Util_Environment_Exceptions
	 */
	public function fix_on_wpadmin_request( $config, $force_all_checks ) {
		$exs = new Util_Environment_Exceptions();

		$this->fix_folders( $config, $exs );

		if ( $config->get_boolean( 'config.check' ) || $force_all_checks ) {
			if ( $config->get_boolean( 'minify.enabled' ) &&
				Util_Rule::can_check_rules() &&
				$config->get_boolean( 'minify.rewrite' ) ) {
				$this->rules_core_add( $config, $exs );
			} else {
				$this->rules_core_remove( $exs );
			}

			if ( $config->get_boolean( 'minify.enabled' ) &&
				$config->get_string( 'minify.engine' ) == 'file' ) {
				$this->rules_cache_add( $config, $exs );
			} else {
				$this->rules_cache_remove( $exs );
			}
		}

		// if no errors so far - check if rewrite actually works
		if ( count( $exs->exceptions() ) <= 0 ) {
			try {
				if ( $config->get_boolean( 'minify.enabled' ) &&
					$config->get_boolean( 'minify.rewrite' ) &&
					$config->get_boolean( 'minify.debug' ) )
					$this->verify_rewrite_working();
			} catch ( \Exception $ex ) {
				$exs->push( $ex );
			}

			if ( $config->get_boolean( 'minify.enabled' ) )
				$this->verify_engine_working( $config, $exs );
		}

		if ( count( $exs->exceptions() ) > 0 )
			throw $exs;
	}

	/**
	 * Fixes environment once event occurs
	 *
	 * @param Config  $config
	 * @param string  $event
	 * @param null|Config $old_config
	 * @throws Util_Environment_Exceptions
	 */
	public function fix_on_event( $config, $event, $old_config = null ) {
		// Schedules events
		if ( $config->get_boolean( 'minify.enabled' ) &&
			$config->get_string( 'minify.engine' ) == 'file' ) {
			if ( $old_config != null &&
				$config->get_integer( 'minify.file.gc' ) !=
				$old_config->get_integer( 'minify.file.gc' ) ) {
				$this->unschedule();
			}

			if ( !wp_next_scheduled( 'w3_minify_cleanup' ) ) {
				wp_schedule_event( time(),
					'w3_minify_cleanup', 'w3_minify_cleanup' );
			}
		} else {
			$this->unschedule();
		}
	}

	/**
	 * Fixes environment after plugin deactivation
	 *
	 * @throws Util_Environment_Exceptions
	 */
	public function fix_after_deactivation() {
		$exs = new Util_Environment_Exceptions();

		$this->rules_core_remove( $exs );
		$this->rules_cache_remove( $exs );

		$this->unschedule();

		if ( count( $exs->exceptions() ) > 0 )
			throw $exs;
	}

	/**
	 *
	 *
	 * @param Config  $config
	 * @return array
	 */
	function get_required_rules( $config ) {
		if ( !$config->get_boolean( 'minify.enabled' ) )
			return null;

		$rewrite_rules = array();
		if ( $config->get_string( 'minify.engine' ) == 'file' ) {
			$minify_rules_cache_path = Util_Rule::get_minify_rules_cache_path();
			$rewrite_rules[] = array(
				'filename' => $minify_rules_cache_path,
				'content'  => $this->rules_cache_generate( $config )
			);
		}
		$minify_rules_core_path = Util_Rule::get_minify_rules_core_path();
		$rewrite_rules[] = array(
			'filename' => $minify_rules_core_path,
			'content'  => $this->rules_core_generate( $config ),
			'priority' => 1000
		);

		return $rewrite_rules;
	}



	/**
	 * Fixes folders
	 *
	 * @param Config  $config
	 * @param Util_Environment_Exceptions $exs
	 */
	private function fix_folders( $config, $exs ) {
		// folder that we delete if exists and not writeable
		if ( $config->get_boolean( 'minify.enabled' ) &&
			$config->get_string( 'minify.engine' ) == 'file' ) {
			$dir = W3TC_CACHE_MINIFY_DIR;

			try{
				if ( file_exists( $dir ) && !is_writeable( $dir ) )
					Util_WpFile::delete_folder( $dir, '', isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' );
			} catch ( Util_WpFile_FilesystemRmdirException $ex ) {
				$exs->push( $ex );
			}
		}
	}

	/**
	 * Minifiers availability error handling
	 *
	 * @param Config  $config
	 * @param Util_Environment_Exceptions $exs
	 */
	private function verify_engine_working( $config, $exs ) {
		$minifiers_errors = array();

		if ( $config->get_string( 'minify.js.engine' ) == 'yuijs' ) {
			$path_java = $config->get_string( 'minify.yuijs.path.java' );
			$path_jar = $config->get_string( 'minify.yuijs.path.jar' );

			if ( !file_exists( $path_java ) ) {
				$minifiers_errors[] = sprintf( 'YUI Compressor (JS): JAVA executable path was not found. The default minifier JSMin will be used instead.' );
			} elseif ( !file_exists( $path_jar ) ) {
				$minifiers_errors[] = sprintf( 'YUI Compressor (JS): JAR file path was not found. The default minifier JSMin will be used instead.' );
			}
		}

		if ( $config->get_string( 'minify.css.engine' ) == 'yuicss' ) {
			$path_java = $config->get_string( 'minify.yuicss.path.java' );
			$path_jar = $config->get_string( 'minify.yuicss.path.jar' );

			if ( !file_exists( $path_java ) ) {
				$minifiers_errors[] = sprintf( 'YUI Compressor (CSS): JAVA executable path was not found. The default CSS minifier will be used instead.' );
			} elseif ( !file_exists( $path_jar ) ) {
				$minifiers_errors[] = sprintf( 'YUI Compressor (CSS): JAR file path was not found. The default CSS minifier will be used instead.' );
			}
		}

		if ( $config->get_string( 'minify.js.engine' ) == 'ccjs' ) {
			$path_java = $config->get_string( 'minify.ccjs.path.java' );
			$path_jar = $config->get_string( 'minify.ccjs.path.jar' );

			if ( !file_exists( $path_java ) ) {
				$minifiers_errors[] = sprintf( 'Closure Compiler: JAVA executable path was not found. The default minifier JSMin will be used instead.' );
			} elseif ( !file_exists( $path_jar ) ) {
				$minifiers_errors[] = sprintf( 'Closure Compiler: JAR file path was not found. The default minifier JSMin will be used instead.' );
			}
		}

		if ( count( $minifiers_errors ) ) {
			$minify_error = 'The following minifiers cannot be found or are no longer working:</p><ul>';

			foreach ( $minifiers_errors as $minifiers_error ) {
				$minify_error .= '<li>' . $minifiers_error . '</li>';
			}

			$minify_error .= '</ul><p>This message will automatically disappear once the issue is resolved.';

			$exs->push( new Util_Environment_Exception( $minify_error ) );
		}
	}

	/**
	 * Checks rewrite
	 *
	 * @throws Util_Environment_Exceptions
	 */
	private function verify_rewrite_working() {
		$url = Minify_Core::minified_url( rand() . 'w3tc_rewrite_test.css' );

		$result = $this->test_rewrite( $url );
		if ( $result != 'ok' ) {
			$home_url = get_home_url();

			$tech_message =
				( Util_Environment::is_nginx() ? 'nginx configuration file' : '.htaccess file' ) .
				' contains rules to rewrite url ' .
				$url . '. If handled by ' .
				'plugin, it returns "Minify OK" message.<br/>';
			$tech_message .= 'The plugin made a request to ' .
				$url . ' but received: <br />' .
				$result . '<br />';
			$tech_message .= 'instead of "Minify OK" response. <br />';

			$error = '<strong>W3 Total Cache error:</strong>It appears Minify ' .
				'<acronym title="Uniform Resource Locator">URL</acronym> ' .
				'rewriting is not working. ';

			if ( Util_Environment::is_nginx() ) {
				$error .= 'Please verify that all configuration files are ' .
					'included in the configuration file ' .
					'(and that you have reloaded / restarted nginx).';
			} else {
				$error .= 'Please verify that the server configuration ' .
					'allows .htaccess';
			}

			$error .= '<br />Unfortunately minification will ' .
				'not function without custom rewrite rules. ' .
				'Please ask your server administrator for assistance. ' .
				'Also refer to <a href="' .
				admin_url( 'admin.php?page=w3tc_install' ) .
				'">the install page</a>  for the rules for your server.';

			throw new Util_Environment_Exception( $error, $tech_message );
		}
	}

	/**
	 * Perform rewrite test
	 *
	 * @param string  $url
	 * @return boolean
	 */
	private function test_rewrite( $url ) {
		$key = sprintf( 'w3tc_rewrite_test_%s', substr( md5( $url ), 0, 16 ) );
		$result = get_site_transient( $key );

		if ( $result != 'ok' ) {
			$response = Util_Http::get( $url );

			$is_ok = ( !is_wp_error( $response ) &&
				$response['response']['code'] == 200 &&
				trim( $response['body'] ) == 'Minify OK' );

			if ( $is_ok )
				$result = 'ok';
			else {
				if ( is_wp_error( $response ) )
					$result = $response->get_error_message();
				else {
					$result = '<pre>' .
						print_r( $response['response'], true ) .
						'</pre>';
				}
			}

			set_site_transient( $key, $result, 30 );
		}

		return $result;
	}



	/**
	 * scheduling stuff
	 */
	private function unschedule() {
		if ( wp_next_scheduled( 'w3_minify_cleanup' ) ) {
			wp_clear_scheduled_hook( 'w3_minify_cleanup' );
		}
	}



	/**
	 * rules core modification
	 */

	/**
	 * Writes directives to WP .htaccess
	 *
	 * @throws Util_WpFile_FilesystemOperationException with S/FTP form if it can't get the required filesystem credentials
	 */
	private function rules_core_add( $config, $exs ) {

		Util_Rule::add_rules( $exs, Util_Rule::get_minify_rules_core_path(),
			$this->rules_core_generate( $config ),
			W3TC_MARKER_BEGIN_MINIFY_CORE,
			W3TC_MARKER_END_MINIFY_CORE,
			array(
				W3TC_MARKER_BEGIN_PGCACHE_CORE => 0,
				W3TC_MARKER_BEGIN_WORDPRESS => 0,
				W3TC_MARKER_END_BROWSERCACHE_CACHE => strlen( W3TC_MARKER_END_BROWSERCACHE_CACHE ) + 1,
				W3TC_MARKER_END_PGCACHE_CACHE => strlen( W3TC_MARKER_END_PGCACHE_CACHE ) + 1,
				W3TC_MARKER_END_MINIFY_CACHE => strlen( W3TC_MARKER_END_MINIFY_CACHE ) + 1
			)
		);
	}

	/**
	 * Removes Page Cache core directives
	 *
	 * @param Util_Environment_Exceptions $exs
	 * @throws Util_WpFile_FilesystemOperationException with S/FTP form if it can't get the required filesystem credentials
	 */
	private function rules_core_remove( $exs ) {
		// no need to remove rules for apache - its in cache .htaccess file
		if ( !Util_Environment::is_nginx() )
			return;

		Util_Rule::remove_rules( $exs,
			Util_Rule::get_minify_rules_core_path(),
			W3TC_MARKER_BEGIN_MINIFY_CORE ,
			W3TC_MARKER_END_MINIFY_CORE );
	}

	/**
	 * Generates rules for WP dir
	 *
	 * @param Config  $config
	 * @return string
	 */
	public function rules_core_generate( $config ) {
		switch ( true ) {
		case Util_Environment::is_apache():
		case Util_Environment::is_litespeed():
			return $this->rules_core_generate_apache( $config );

		case Util_Environment::is_nginx():
			return $this->rules_core_generate_nginx( $config );
		}

		return '';
	}

	private function site_uri() {
		$site_uri = rtrim( network_site_url( '', 'relative' ), '/' ) . '/';

		/* There is a bug in WP where network_home_url can return
		 * a non-relative URI even though scheme is set to relative.
		 */
		if ( Util_Environment::is_url( $site_uri ) ) {
			$site_uri = parse_url( $site_uri, PHP_URL_PATH );
		}

		return $site_uri;
	}

	/**
	 * Generates rules
	 *
	 * @param Config  $config
	 * @return string
	 */
	function rules_core_generate_apache( $config ) {
		$cache_uri = Util_Environment::url_to_uri(
			Util_Environment::filename_to_url( W3TC_CACHE_MINIFY_DIR ) ) . '/';
		$site_uri = $this->site_uri();

		/* There is a bug in WP where network_home_url can return
		 * a non-relative URI even though scheme is set to relative.
		 */
		if ( Util_Environment::is_url( $site_uri ) ) {
			$site_uri = parse_url( $site_uri, PHP_URL_PATH );
		}

		$engine = $config->get_string( 'minify.engine' );
		$browsercache = $config->get_boolean( 'browsercache.enabled' );
		$brotli = ( $browsercache &&
			$config->get_boolean( 'browsercache.cssjs.brotli' ) &&
			!defined( 'W3TC_PAGECACHE_OUTPUT_COMPRESSION_OFF' ) );
		$compression = ( $browsercache &&
			$config->get_boolean( 'browsercache.cssjs.compression' ) &&
			!defined( 'W3TC_PAGECACHE_OUTPUT_COMPRESSION_OFF' ) );

		$rules = '';
		$rules .= W3TC_MARKER_BEGIN_MINIFY_CORE . "\n";
		$rules .= "<IfModule mod_rewrite.c>\n";
		$rules .= "    RewriteEngine On\n";
		$rules .= "    RewriteBase " . $cache_uri . "\n";

		if ( $engine == 'file' ) {
			if ( $brotli ) {
				$rules .= "    RewriteCond %{HTTP:Accept-Encoding} br\n";
				$rules .= "    RewriteRule .* - [E=APPEND_EXT:_br]\n";
				$rules .= "    RewriteCond %{REQUEST_FILENAME}%{ENV:APPEND_EXT} -" . ( $config->get_boolean( 'minify.file.nfs' ) ? 'F' : 'f' ) . "\n";
				$rules .= "    RewriteRule (.*) $1%{ENV:APPEND_EXT} [L]\n";
			}
			if ( $compression ) {
				$rules .= "    RewriteCond %{HTTP:Accept-Encoding} gzip\n";
				$rules .= "    RewriteRule .* - [E=APPEND_EXT:_gzip]\n";
				$rules .= "    RewriteCond %{REQUEST_FILENAME}%{ENV:APPEND_EXT} -" . ( $config->get_boolean( 'minify.file.nfs' ) ? 'F' : 'f' ) . "\n";
				$rules .= "    RewriteRule (.*) $1%{ENV:APPEND_EXT} [L]\n";
			}
			if ( !$brotli && !$compression ) {
				$rules .= "    RewriteCond %{REQUEST_FILENAME} !-f\n";
			}
		}
		$rules .= "    RewriteRule ^(.+\\.(css|js))$ {$site_uri}index.php [L]\n";

		$rules .= "</IfModule>\n";
		$rules .= W3TC_MARKER_END_MINIFY_CORE . "\n";

		return $rules;
	}

	/**
	 * Generates rules
	 *
	 * @param Config  $config
	 * @return string
	 */
	function rules_core_generate_nginx( $config ) {
		$cache_uri = Util_Environment::url_to_uri(
			Util_Environment::filename_to_url( W3TC_CACHE_MINIFY_DIR ) ) . '/';
		$first_regex_var = '$1';

		// for subdir - need to count subdir in url
		if ( Util_Environment::is_wpmu() && !Util_Environment::is_wpmu_subdomain() ) {
			// take into accont case when whole subdir wpmu is installed in subdir
			$home_uri = network_home_url( '', 'relative' );
			if ( substr( $cache_uri, 0, strlen( $home_uri ) ) == $home_uri )
				$cache_uri = $home_uri . '([a-z0-9]+/)?' .
					substr( $cache_uri, strlen( $home_uri ) );
			else
				$cache_uri = '(/[a-z0-9]+)?' . $cache_uri;

			$first_regex_var = '$2';
		}

		$minify_uri = $this->site_uri();

		$engine = $config->get_string( 'minify.engine' );
		$browsercache = $config->get_boolean( 'browsercache.enabled' );
		$brotli = ( $browsercache &&
			$config->get_boolean( 'browsercache.cssjs.brotli' ) &&
			!defined( 'W3TC_PAGECACHE_OUTPUT_COMPRESSION_OFF' ) );
		$compression = ( $browsercache &&
			$config->get_boolean( 'browsercache.cssjs.compression' ) &&
			!defined( 'W3TC_PAGECACHE_OUTPUT_COMPRESSION_OFF' ) );

		$rules = '';
		$rules .= W3TC_MARKER_BEGIN_MINIFY_CORE . "\n";

		if ( $engine == 'file' ) {
			$rules .= "set \$w3tc_enc \"\";\n";

			if ( $brotli ) {
				$rules .= "if (\$http_accept_encoding ~ br) {\n";
				$rules .= "    set \$w3tc_enc _br;\n";
				$rules .= "}\n";
			}

			if ( $compression ) {
				$rules .= "if (\$http_accept_encoding ~ gzip) {\n";
				$rules .= "    set \$w3tc_enc _gzip;\n";
				$rules .= "}\n";
			}

			$rules .= "if (-f \$request_filename\$w3tc_enc) {\n";
			$rules .= "    rewrite (.*) $1\$w3tc_enc break;\n";
			$rules .= "}\n";
		}
		$rules .= "rewrite ^$cache_uri {$minify_uri}index.php last;\n";
		$rules .= W3TC_MARKER_END_MINIFY_CORE . "\n";

		return $rules;
	}



	/*
	 * cache rules
	 */

	/**
	 * Writes directives to file cache .htaccess
	 * Throws exception on error
	 *
	 * @param Config  $config
	 * @param Util_Environment_Exceptions $exs
	 */
	private function rules_cache_add( $config, $exs ) {
		Util_Rule::add_rules( $exs,
			Util_Rule::get_minify_rules_cache_path(),
			$this->rules_cache_generate( $config ),
			W3TC_MARKER_BEGIN_MINIFY_CACHE,
			W3TC_MARKER_END_MINIFY_CACHE,
			array(
				W3TC_MARKER_BEGIN_PGCACHE_CACHE => 0,
				W3TC_MARKER_BEGIN_BROWSERCACHE_CACHE => 0,
				W3TC_MARKER_BEGIN_MINIFY_CORE => 0,
				W3TC_MARKER_BEGIN_PGCACHE_CORE => 0,
				W3TC_MARKER_BEGIN_WORDPRESS => 0
			)
		);
	}

	/**
	 * Removes Page Cache core directives
	 *
	 * @param Util_Environment_Exceptions $exs
	 * @throws Util_WpFile_FilesystemOperationException with S/FTP form if it can't get the required filesystem credentials
	 */
	private function rules_cache_remove( $exs ) {
		// apache's cache files are not used when core rules disabled
		if ( !Util_Environment::is_nginx() )
			return;

		Util_Rule::remove_rules( $exs,
			Util_Rule::get_minify_rules_cache_path(),
			W3TC_MARKER_BEGIN_MINIFY_CACHE,
			W3TC_MARKER_END_MINIFY_CACHE );

	}

	/**
	 * Generates directives for file cache dir
	 *
	 * @param Config  $config
	 * @return string
	 */
	private function rules_cache_generate( $config ) {
		switch ( true ) {
		case Util_Environment::is_apache():
		case Util_Environment::is_litespeed():
			return $this->rules_cache_generate_apache( $config );

		case Util_Environment::is_nginx():
			return $this->rules_cache_generate_nginx( $config );
		}

		return '';
	}


	/**
	 * Generates directives for file cache dir
	 *
	 * @param Config  $config
	 * @return string
	 */
	private function rules_cache_generate_apache( $config ) {
		$browsercache = $config->get_boolean( 'browsercache.enabled' );
		$brotli = ( $browsercache && $config->get_boolean( 'browsercache.cssjs.brotli' ) );
		$compression = ( $browsercache && $config->get_boolean( 'browsercache.cssjs.compression' ) );
		$expires = ( $browsercache && $config->get_boolean( 'browsercache.cssjs.expires' ) );
		$lifetime = ( $browsercache ? $config->get_integer( 'browsercache.cssjs.lifetime' ) : 0 );
		$cache_control = ( $browsercache && $config->get_boolean( 'browsercache.cssjs.cache.control' ) );
		$etag = ( $browsercache && $config->get_integer( 'browsercache.html.etag' ) );
		$w3tc = ( $browsercache && $config->get_integer( 'browsercache.cssjs.w3tc' ) );
		$compatibility = $config->get_boolean( 'pgcache.compatibility' );

		$rules = '';
		$rules .= W3TC_MARKER_BEGIN_MINIFY_CACHE . "\n";
		// workaround for .gzip
		if ( $compatibility ) {
			$rules .= "Options -MultiViews\n";
		}

		if ( $etag ) {
			$rules .= "FileETag MTime Size\n";
		}

		if ( $brotli ) {
			$rules .= "<IfModule mod_mime.c>\n";
			$rules .= "    AddType text/css .css_br\n";
			$rules .= "    AddEncoding br .css_br\n";
			$rules .= "    AddType application/x-javascript .js_br\n";
			$rules .= "    AddEncoding br .js_br\n";
			$rules .= "</IfModule>\n";
			$rules .= "<IfModule mod_deflate.c>\n";
			$rules .= "    <IfModule mod_setenvif.c>\n";
			$rules .= "        SetEnvIfNoCase Request_URI \\.css_br$ no-brotli\n";
			$rules .= "        SetEnvIfNoCase Request_URI \\.js_br$ no-brotli\n";
			$rules .= "    </IfModule>\n";
			$rules .= "</IfModule>\n";
		}

		if ( $compression ) {
			$rules .= "<IfModule mod_mime.c>\n";
			$rules .= "    AddType text/css .css_gzip\n";
			$rules .= "    AddEncoding gzip .css_gzip\n";
			$rules .= "    AddType application/x-javascript .js_gzip\n";
			$rules .= "    AddEncoding gzip .js_gzip\n";
			$rules .= "</IfModule>\n";
			$rules .= "<IfModule mod_deflate.c>\n";
			$rules .= "    <IfModule mod_setenvif.c>\n";
			$rules .= "        SetEnvIfNoCase Request_URI \\.css_gzip$ no-gzip\n";
			$rules .= "        SetEnvIfNoCase Request_URI \\.js_gzip$ no-gzip\n";
			$rules .= "    </IfModule>\n";
			$rules .= "</IfModule>\n";
		}

		if ( $expires ) {
			$rules .= "<IfModule mod_expires.c>\n";
			$rules .= "    ExpiresActive On\n";
			$rules .= "    ExpiresByType text/css A" . $lifetime . "\n";
			$rules .= "    ExpiresByType application/x-javascript A" . $lifetime . "\n";
			$rules .= "</IfModule>\n";
		}

		if ( $w3tc || $brotli || $compression || $cache_control ) {
			$rules .= "<IfModule mod_headers.c>\n";

			if ( $w3tc ) {
				$rules .= "    Header set X-Powered-By \"" .
					Util_Environment::w3tc_header() . "\"\n";
			}

			if ( $brotli || $compression ) {
				$rules .= "    Header set Vary \"Accept-Encoding\"\n";
			}

			if ( $cache_control ) {
				$cache_policy = $config->get_string( 'browsercache.cssjs.cache.policy' );

				switch ( $cache_policy ) {
				case 'cache':
					$rules .= "    Header set Pragma \"public\"\n";
					$rules .= "    Header set Cache-Control \"public\"\n";
					break;

				case 'cache_public_maxage':
					$rules .= "    Header set Pragma \"public\"\n";

					if ( $expires ) {
						$rules .= "    Header append Cache-Control \"public\"\n";
					} else {
						$rules .= "    Header set Cache-Control \"max-age=" . $lifetime . ", public\"\n";
					}
					break;

				case 'cache_validation':
					$rules .= "    Header set Pragma \"public\"\n";
					$rules .= "    Header set Cache-Control \"public, must-revalidate, proxy-revalidate\"\n";
					break;

				case 'cache_noproxy':
					$rules .= "    Header set Pragma \"public\"\n";
					$rules .= "    Header set Cache-Control \"private, must-revalidate\"\n";
					break;

				case 'cache_maxage':
					$rules .= "    Header set Pragma \"public\"\n";

					if ( $expires ) {
						$rules .= "    Header append Cache-Control \"public, must-revalidate, proxy-revalidate\"\n";
					} else {
						$rules .= "    Header set Cache-Control \"max-age=" . $lifetime . ", public, must-revalidate, proxy-revalidate\"\n";
					}
					break;

				case 'no_cache':
					$rules .= "    Header set Pragma \"no-cache\"\n";
					$rules .= "    Header set Cache-Control \"max-age=0, private, no-store, no-cache, must-revalidate\"\n";
					break;
				}
			}

			$rules .= "</IfModule>\n";
		}

		$rules .= W3TC_MARKER_END_MINIFY_CACHE . "\n";

		return $rules;
	}

	/**
	 * Generates directives for file cache dir
	 *
	 * @param Config  $config
	 * @return string
	 */
	private function rules_cache_generate_nginx( $config ) {
		$cache_uri = Util_Environment::url_to_uri(
			Util_Environment::filename_to_url( W3TC_CACHE_MINIFY_DIR ) ) . '/';

		$browsercache = $config->get_boolean( 'browsercache.enabled' );
		$brotli = ( $browsercache && $config->get_boolean( 'browsercache.cssjs.brotli' ) );
		$gzip = ( $browsercache && $config->get_boolean( 'browsercache.cssjs.compression' ) );

		$rules = '';
		$rules .= W3TC_MARKER_BEGIN_MINIFY_CACHE . "\n";

		$common_rules_a = Dispatcher::nginx_rules_for_browsercache_section(
			$config, 'cssjs', true );
		$common_rules_a[] = 'add_header Vary "Accept-Encoding";';

		$common_rules = '    ' . implode( "\n    ", $common_rules_a ) . "\n";

		if ( $brotli ) {
			$rules .= "location ~ " . $cache_uri . ".*js_br$ {\n";
			$rules .= "    brotli off;\n";
			$rules .= "    types {}\n";
			$rules .= "    default_type application/x-javascript;\n";
			$rules .= "    add_header Content-Encoding br;\n";
			$rules .= $common_rules;
			$rules .= "}\n";

			$rules .= "location ~ " . $cache_uri . ".*css_br$ {\n";
			$rules .= "    brotli off;\n";
			$rules .= "    types {}\n";
			$rules .= "    default_type text/css;\n";
			$rules .= "    add_header Content-Encoding br;\n";
			$rules .= $common_rules;
			$rules .= "}\n";
		}

		if ( $gzip ) {
			$rules .= "location ~ " . $cache_uri . ".*js_gzip$ {\n";
			$rules .= "    gzip off;\n";
			$rules .= "    types {}\n";
			$rules .= "    default_type application/x-javascript;\n";
			$rules .= "    add_header Content-Encoding gzip;\n";
			$rules .= $common_rules;
			$rules .= "}\n";

			$rules .= "location ~ " . $cache_uri . ".*css_gzip$ {\n";
			$rules .= "    gzip off;\n";
			$rules .= "    types {}\n";
			$rules .= "    default_type text/css;\n";
			$rules .= "    add_header Content-Encoding gzip;\n";
			$rules .= $common_rules;
			$rules .= "}\n";
		}

		$rules .= W3TC_MARKER_END_MINIFY_CACHE . "\n";

		return $rules;
	}

	public function w3tc_browsercache_rules_section( $section_rules, $config, $section ) {
		if ( Util_Environment::is_litespeed() ) {
			$o = new Minify_Environment_LiteSpeed( $config );
			$section_rules = $o->w3tc_browsercache_rules_section(
				$section_rules, $section );
		}
		return $section_rules;
	}
}
