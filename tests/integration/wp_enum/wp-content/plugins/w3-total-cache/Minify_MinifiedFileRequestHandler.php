<?php
namespace W3TC;

// Define repeated regex to simplify changes
define( 'MINIFY_AUTO_FILENAME_REGEX', '([a-zA-Z0-9-_]+)\\.(css|js)([?].*)?' );
define( 'MINIFY_MANUAL_FILENAME_REGEX', '([a-f0-9]+)\\.(.+)\\.(include(\\-(footer|body))?)\\.[a-f0-9]+\\.(css|js)' );
/**
 * class Minify_MinifiedFileRequestHandler
 */
class Minify_MinifiedFileRequestHandler {
	/**
	 * Config
	 */
	var $_config = null;

	/**
	 * Tracks if an error has occurred.
	 *
	 * @var bool
	 */
	var $_error_occurred = false;

	/**
	 * PHP5 constructor
	 */
	function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Runs minify
	 *
	 * @param string|null $file
	 *
	 * @return void
	 */
	function process( $file = NULL, $quiet = false ) {
		/**
		 * Check for rewrite test request
		 */
		$rewrite_marker = 'rewrite_test.css';
		if ( substr( $file, strlen( $file ) - strlen( $rewrite_marker ) ) ==
			$rewrite_marker ) {
			echo 'Minify OK';
			exit();
		}

		$filelength_test_marker = 'XXX.css';
		if ( substr( $file, strlen( $file ) - strlen( $filelength_test_marker ) ) ==
			$filelength_test_marker ) {
			$cache = $this->_get_cache();
			header( 'Content-type: text/css' );

			if ( ! $cache->store( basename( $file ), array( 'content' => 'content ok' ) ) ) {
				echo 'error storing';
			} else {
				if ( ( function_exists( 'brotli_compress' ) &&
					   $this->_config->get_boolean( 'browsercache.enabled' ) &&
					   $this->_config->get_boolean( 'browsercache.cssjs.brotli' ) ) )
					if ( !$cache->store( basename( $file ) . '_br',
						array( 'content' => brotli_compress( 'content ok' ) ) ) ) {
						echo 'error storing';
						exit();
					}

				if ( ( function_exists( 'gzencode' ) &&
						$this->_config->get_boolean( 'browsercache.enabled' ) &&
						$this->_config->get_boolean( 'browsercache.cssjs.compression' ) ) )
					if ( !$cache->store( basename( $file ) . '_gzip',
							array( 'content' => gzencode( 'content ok' ) ) ) ) {
						echo 'error storing';
						exit();
					}

				$v = $cache->fetch( basename( $file ) );
				if ( $v['content'] == 'content ok' )
					echo 'content ok';
				else
					echo 'error storing';
			}

			exit();
		}

		// remove querystring
		if ( preg_match( '~(.+)(\?x[0-9]{5})$~', $file, $m ) )
			$file = $m[1];

		// remove blog_id
		$levels = '';
		if ( defined( 'W3TC_BLOG_LEVELS' ) ) {
			for ( $n = 0; $n < W3TC_BLOG_LEVELS; $n++ )
				$levels .= '[0-9]+\/';
		}

		if ( preg_match( '~^(' . $levels . '[0-9]+)\/(.+)$~', $file, $matches ) )
			$file = $matches[2];

		// normalize according to browsercache
		$file = Dispatcher::requested_minify_filename( $this->_config, $file );

		// parse file
		$hash = '';
		$matches = null;
		$location = '';
		$type = '';

		if ( preg_match( '~^' . MINIFY_AUTO_FILENAME_REGEX .'$~', $file, $matches ) ) {
			list( , $hash, $type ) = $matches;
		} elseif ( preg_match( '~^' . MINIFY_MANUAL_FILENAME_REGEX . '$~', $file, $matches ) ) {
			list( , $theme, $template, $location, , , $type ) = $matches;
		} else {
			return $this->finish_with_error( sprintf( 'Bad file param format: "%s"', $file ), $quiet, false );
		}

		/**
		 * Set cache engine
		 */
		$cache = $this->_get_cache();
		\W3TCL\Minify\Minify::setCache( $cache );

		/**
		 * Set cache ID
		 */
		$cache_id = $this->get_cache_id( $file );
		\W3TCL\Minify\Minify::setCacheId( $file );

		/**
		 * Set logger
		 */
		\W3TCL\Minify\Minify_Logger::setLogger( array(
				$this,
				'debug_error' ) );

		/**
		 * Set options
		 */
		$browsercache = $this->_config->get_boolean( 'browsercache.enabled' );

		$serve_options = array_merge( $this->_config->get_array( 'minify.options' ), array(
				'debug' => $this->_config->get_boolean( 'minify.debug' ),
				'maxAge' => $this->_config->get_integer( 'browsercache.cssjs.lifetime' ),
				'encodeOutput' => ( $browsercache &&
					!defined( 'W3TC_PAGECACHE_OUTPUT_COMPRESSION_OFF' ) &&
					!$quiet &&
					( $this->_config->get_boolean( 'browsercache.cssjs.compression' ) ||
					$this->_config->get_boolean( 'browsercache.cssjs.brotli' ) ) ),
				'bubbleCssImports' => ( $this->_config->get_string( 'minify.css.imports' ) == 'bubble' ),
				'processCssImports' => ( $this->_config->get_string( 'minify.css.imports' ) == 'process' ),
				'cacheHeaders' => array(
					'use_etag' => ( $browsercache && $this->_config->get_boolean( 'browsercache.cssjs.etag' ) ),
					'expires_enabled' => ( $browsercache && $this->_config->get_boolean( 'browsercache.cssjs.expires' ) ),
					'cacheheaders_enabled' => ( $browsercache && $this->_config->get_boolean( 'browsercache.cssjs.cache.control' ) ),
					'cacheheaders' => $this->_config->get_string( 'browsercache.cssjs.cache.policy' )
				),
				'disable_304' => $quiet,   // when requested for service needs - need content instead of 304
				'quiet' => $quiet
			) );

		/**
		 * Set sources
		 */
		if ( $hash ) {
			$_GET['f_array'] = $this->minify_filename_to_filenames_for_minification( $hash, $type );
			$_GET['ext'] = $type;
		} else {
			$_GET['g'] = $location;
			$serve_options['minApp']['groups'] = $this->get_groups( $theme, $template, $type );
		}

		/**
		 * Set minifier
		 */
		$w3_minifier = Dispatcher::component( 'Minify_ContentMinifier' );

		if ( $type == 'js' ) {
			$minifier_type = 'application/x-javascript';

			switch ( true ) {
			case ( $hash && $this->_config->get_string( 'minify.js.method' ) == 'combine' ):
			case ( $location == 'include' && $this->_config->get_boolean( 'minify.js.combine.header' ) ):
			case ( $location == 'include-body' && $this->_config->get_boolean( 'minify.js.combine.body' ) ):
			case ( $location == 'include-footer' && $this->_config->get_boolean( 'minify.js.combine.footer' ) ):
				$engine = 'combinejs';
				break;

			default:
				$engine = $this->_config->get_string( 'minify.js.engine' );

				if ( !$w3_minifier->exists( $engine ) || !$w3_minifier->available( $engine ) ) {
					$engine = 'js';
				}
				break;
			}

		} elseif ( $type == 'css' ) {
			$minifier_type = 'text/css';

			if ( ( $hash || $location == 'include' ) && $this->_config->get_string( 'minify.css.method' ) == 'combine' ) {
				$engine = 'combinecss';
			} else {
				$engine = $this->_config->get_string( 'minify.css.engine' );

				if ( !$w3_minifier->exists( $engine ) || !$w3_minifier->available( $engine ) ) {
					$engine = 'css';
				}
			}
		}

		/**
		 * Initialize minifier
		 */
		$w3_minifier->init( $engine );

		$serve_options['minifiers'][$minifier_type] = $w3_minifier->get_minifier( $engine );
		$serve_options['minifierOptions'][$minifier_type] = $w3_minifier->get_options( $engine );

		/**
		 * Send X-Powered-By header
		 */
		if ( !$quiet && $browsercache && $this->_config->get_boolean( 'browsercache.cssjs.w3tc' ) ) {
			@header( 'X-Powered-By: ' . Util_Environment::w3tc_header() );
		}

		if ( empty( Util_Request::get( 'f_array' ) ) && empty( Util_Request::get_string( 'g' ) ) ) {
			return $this->finish_with_error( 'Nothing to minify', $quiet, false );
		}

		// Minify
		$serve_options = apply_filters(
			'w3tc_minify_file_handler_minify_options',
			$serve_options );

		$return = array();
		try {
			$return = \W3TCL\Minify\Minify::serve( 'MinApp', $serve_options );
		} catch ( \Exception $exception ) {
			return $this->finish_with_error( $exception->getMessage(), $quiet );
		}

		if ( !is_null( \W3TCL\Minify\Minify::$recoverableError ) )
			$this->_handle_error( \W3TCL\Minify\Minify::$recoverableError );

		$state = Dispatcher::config_state_master();
		if ( !$this->_error_occurred && $state->get_boolean( 'minify.show_note_minify_error' ) ) {
			$error_file = $state->get_string( 'minify.error.file' );
			if ( $error_file == $file ) {
				$state->set( 'minify.show_note_minify_error', false );
				$state->save();
			}
		}

		return $return;
	}



	public function w3tc_usage_statistics_of_request( $storage ) {
		$stats = \W3TCL\Minify\Minify::getUsageStatistics();
		if ( count( $stats ) > 0 ) {
			$storage->counter_add( 'minify_requests_total', 1 );
			if ( $stats['content_type'] == 'text/css' ) {
				$storage->counter_add( 'minify_original_length_css',
					(int)( $stats['content_original_length'] / 102.4 ) );
				$storage->counter_add( 'minify_output_length_css',
					(int)( $stats['content_output_length'] / 102.4 ) );
			} else {
				$storage->counter_add( 'minify_original_length_js',
					(int)( $stats['content_original_length'] / 102.4 ) );
				$storage->counter_add( 'minify_output_length_js',
					(int)( $stats['content_output_length'] / 102.4 ) );
			}
		}
	}



	/**
	 * Returns size statistics about cache files
	 */
	public function get_stats_size( $timeout_time ) {
		$cache = $this->_get_cache();
		if ( method_exists( $cache, 'get_stats_size' ) )
			return $cache->get_stats_size( $timeout_time );

		return array();
	}



	/**
	 * Flushes cache
	 *
	 * @return boolean
	 */
	function flush() {
		$cache = $this->_get_cache();
		// used to debug - which plugin calls flush all the time and breaks
		// performance
		if ( $this->_config->get_boolean( 'minify.debug' ) ) {
			Minify_Core::log( 'Minify flush called from' );
			Minify_Core::log( json_encode( debug_backtrace () ) );
		}

		return $cache->flush();
	}

	/**
	 * Returns custom data storage for minify file, based on url
	 *
	 * @param string  $url
	 * @return mixed
	 */
	function get_url_custom_data( $url ) {
		if ( preg_match( '~/' . MINIFY_AUTO_FILENAME_REGEX .'$~', $url, $matches ) ) {
			list( , $hash, $type ) = $matches;

			$key = $this->get_custom_data_key( $hash, $type );
			return $this->_cache_get( $key );
		}

		return null;
	}

	/**
	 * Returns custom data storage for minify file
	 *
	 * @param string  $file
	 * @param mixed   $data
	 */
	function set_file_custom_data( $file, $data ) {
		if ( preg_match( '~' . MINIFY_AUTO_FILENAME_REGEX .'$~', $file, $matches ) ) {
			list( , $hash, $type ) = $matches;

			$key = $this->get_custom_data_key( $hash, $type );
			$this->_cache_set( $key, $data );
		}
	}

	/**
	 * Returns minify groups
	 *
	 * @param string  $theme
	 * @param string  $template
	 * @param string  $type
	 * @return array
	 */
	function get_groups( $theme, $template, $type ) {
		$result = array();

		switch ( $type ) {
		case 'css':
			$groups = $this->_config->get_array( 'minify.css.groups' );
			break;

		case 'js':
			$groups = $this->_config->get_array( 'minify.js.groups' );
			break;

		default:
			return $result;
		}

		if ( isset( $groups[$theme]['default'] ) ) {
			$locations = (array) $groups[$theme]['default'];
		} else {
			$locations = array();
		}

		if ( $template != 'default' && isset( $groups[$theme][$template] ) ) {
			$locations = array_merge_recursive( $locations, (array) $groups[$theme][$template] );
		}

		foreach ( $locations as $location => $config ) {
			if ( !empty( $config['files'] ) ) {
				foreach ( (array) $config['files'] as $url ) {
					if ( !Util_Environment::is_url( $url ) )
						$url = Util_Environment::home_domain_root_url() . '/' .
							ltrim( $url, '/' );

					$file = Util_Environment::url_to_docroot_filename( $url );

					if ( is_null( $file ) ) {
						// it's external url
						$precached_file = $this->_precache_file( $url, $type );

						if ( $precached_file ) {
							$result[$location][$url] = $precached_file;
						} else {
							Minify_Core::debug_error( sprintf( 'Unable to cache remote url: "%s"', $url ) );
						}
					} else {
						$path = Util_Environment::document_root() . '/' . $file;

						if ( file_exists( $path ) ) {
							$result[$location][$file] = '//' . $file;
						} else {
							Minify_Core::debug_error( sprintf( 'File "%s" doesn\'t exist', $path ) );
						}
					}
				}
			}
		}

		return $result;
	}

	/**
	 * Returns minify cache ID
	 *
	 * @param string  $file
	 * @return string
	 */
	function get_cache_id( $file ) {
		return $file;
	}

	/**
	 * Returns array of group sources
	 *
	 * @param string  $theme
	 * @param string  $template
	 * @param string  $location
	 * @param string  $type
	 * @return array
	 */
	function get_sources_group( $theme, $template, $location, $type ) {
		$sources = array();
		$groups = $this->get_groups( $theme, $template, $type );

		if ( isset( $groups[$location] ) ) {
			$files = (array) $groups[$location];

			$document_root = Util_Environment::document_root();

			foreach ( $files as $file ) {
				if ( is_a( $file, '\W3TCL\Minify\Minify_Source' ) ) {
					$path = $file->filepath;
				} else {
					$path = rtrim( $document_root, '/' ) . '/' . ltrim( $file, '/' );
				}

				$sources[] = $path;
			}
		}

		return $sources;
	}

	/**
	 * Returns ID key for group
	 *
	 * @param unknown $theme
	 * @param unknown $template
	 * @param unknown $location
	 * @param unknown $type
	 * @return string
	 */
	function get_id_key_group( $theme, $template, $location, $type ) {
		return sprintf( '%s/%s.%s.%s.id', $theme, $template, $location, $type );
	}

	/**
	 * Returns id for group
	 *
	 * @param string  $theme
	 * @param string  $template
	 * @param string  $location
	 * @param string  $type
	 * @return integer
	 */
	function get_id_group( $theme, $template, $location, $type ) {
		$key = $this->get_id_key_group( $theme, $template, $location, $type );
		$id = $this->_cache_get( $key );

		if ( $id === false ) {
			$sources = $this->get_sources_group( $theme, $template, $location, $type );

			if ( count( $sources ) ) {
				$id = $this->_generate_id( $sources, $type );

				if ( $id ) {
					$this->_cache_set( $key, $id );
				}
			}
		}

		return $id;
	}

	/**
	 * Returns custom files key
	 *
	 * @param string  $hash
	 * @param string  $type
	 * @return string
	 */
	function get_custom_data_key( $hash, $type ) {
		return sprintf( '%s.%s.customdata', $hash, $type );
	}

	/**
	 * Returns custom files
	 *
	 * @param string  $hash
	 * @param string  $type
	 * @return array
	 */
	function minify_filename_to_filenames_for_minification( $hash, $type ) {
		// if bad data passed as get parameter - it shouldn't fire internal errors
		try {
			$files = Minify_Core::minify_filename_to_urls_for_minification(
				$hash, $type );
		} catch ( \Exception $e ) {
			$files = array();
		}

		$result = array();
		if ( is_array( $files ) && count( $files ) > 0 ) {
			foreach ( $files as $file ) {
				$docroot_filename = Util_Environment::url_to_docroot_filename( $file );

				if ( Util_Environment::is_url( $file ) && is_null( $docroot_filename ) ) {
					// it's external url
					$precached_file = $this->_precache_file( $file, $type );

					if ( $precached_file ) {
						$result[] = $precached_file;
					} else {
						Minify_Core::debug_error( sprintf( 'Unable to cache remote file: "%s"', $file ) );
					}
				} else {
					$path = Util_Environment::docroot_to_full_filename( $docroot_filename );

					if ( @file_exists( $path ) ) {
						$result[] = $file;
					} else {
						Minify_Core::debug_error( sprintf( 'File "%s" doesn\'t exist', $file ) );
					}
				}
			}
		} else {
			Minify_Core::debug_error( sprintf( 'Unable to fetch custom files list: "%s.%s"', $hash, $type ), false, 404 );
		}

		return $result;
	}

	/**
	 * Sends error response
	 *
	 * @param string  $error
	 * @param boolean $handle
	 * @param integer $status
	 * @return void
	 */
	function finish_with_error( $error, $quiet = false, $report_about_error = true ) {
		$this->_error_occurred = true;

		Minify_Core::debug_error( $error );

		if ( $report_about_error ) {
			$this->_handle_error( $error );
		}

		$message = '<h1>W3TC Minify Error</h1>';

		if ( $this->_config->get_boolean( 'minify.debug' ) ) {
			$message .= sprintf( '<p>%s.</p>', $error );
		} else {
			$message .= '<p>Enable debug mode to see error message.</p>';
		}

		if ( $quiet ) {
			return array(
				'content' => $message
			);
		}

		if ( defined( 'W3TC_IN_MINIFY' ) ) {
			status_header( 400 );
			echo esc_html( $message );
			die();
		}
	}



	public function debug_error( $error ) {
		Minify_Core::debug_error( $error );
	}

	/**
	 * Pre-caches external file
	 *
	 * @param string  $url
	 * @param string  $type
	 * @return string
	 */
	function _precache_file( $url, $type ) {
		$lifetime = $this->_config->get_integer( 'minify.lifetime' );
		$cache_path = sprintf( '%s/minify_%s.%s', Util_Environment::cache_blog_dir( 'minify' ), md5( $url ), $type );

		if ( !file_exists( $cache_path ) || @filemtime( $cache_path ) < ( time() - $lifetime ) ) {
			if ( !@is_dir( dirname( $cache_path ) ) ) {
				Util_File::mkdir_from_safe( dirname( $cache_path ), W3TC_CACHE_DIR );
			}

			// google-fonts (most used for external inclusion)
			// doesnt return full content (unicode-range) for simple useragents
			Util_Http::download( $url, $cache_path,
				array( 'user-agent' =>
					'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.92' ) );
		}

		return file_exists( $cache_path ) ? $this->_get_minify_source( $cache_path, $url ) : false;
	}

	/**
	 * Returns minify source
	 *
	 * @param unknown $file_path
	 * @param unknown $url
	 * @return Minify_Source
	 */
	function _get_minify_source( $file_path, $url ) {
		return new \W3TCL\Minify\Minify_Source( array(
				'filepath' => $file_path,
				'minifyOptions' => array(
					'prependRelativePath' => $url
				)
			) );
	}

	/**
	 * Returns minify cache object
	 *
	 * @return object
	 */
	function _get_cache() {
		static $cache = null;

		if ( is_null( $cache ) ) {
			$inner_cache = null;

			switch ( $this->_config->get_string( 'minify.engine' ) ) {
			case 'memcached':
				$config = array(
					'blog_id' => Util_Environment::blog_id(),
					'instance_id' => Util_Environment::instance_id(),
					'host' =>  Util_Environment::host(),
					'module' => 'minify',
					'servers' => $this->_config->get_array( 'minify.memcached.servers' ),
					'persistent' => $this->_config->get_boolean( 'minify.memcached.persistent' ),
					'aws_autodiscovery' => $this->_config->get_boolean( 'minify.memcached.aws_autodiscovery' ),
					'username' => $this->_config->get_string( 'minify.memcached.username' ),
					'password' => $this->_config->get_string( 'minify.memcached.password' ),
					'binary_protocol' => $this->_config->get_boolean( 'minify.memcached.binary_protocol' )
				);
				if ( class_exists( 'Memcached' ) ) {
					$inner_cache = new Cache_Memcached( $config );
				} elseif ( class_exists( 'Memcache' ) ) {
					$inner_cache = new Cache_Memcache( $config );
				}
				break;

			case 'redis':
				$config = array(
					'blog_id' => Util_Environment::blog_id(),
					'instance_id' => Util_Environment::instance_id(),
					'host' =>  Util_Environment::host(),
					'module' => 'minify',
					'servers' => $this->_config->get_array( 'minify.redis.servers' ),
					'verify_tls_certificates' => $this->_config->get_boolean( 'minify.redis.verify_tls_certificates' ),
					'persistent' => $this->_config->get_boolean( 'minify.redis.persistent' ),
					'timeout' => $this->_config->get_integer( 'minify.redis.timeout' ),
					'retry_interval' => $this->_config->get_integer( 'minify.redis.retry_interval' ),
					'read_timeout' => $this->_config->get_integer( 'minify.redis.read_timeout' ),
					'dbid' => $this->_config->get_integer( 'minify.redis.dbid' ),
					'password' => $this->_config->get_string( 'minify.redis.password' )
				);
				$inner_cache = new Cache_Redis( $config );

				break;

			case 'apc':
				$config = array(
					'blog_id' => Util_Environment::blog_id(),
					'instance_id' => Util_Environment::instance_id(),
					'host' =>  Util_Environment::host(),
					'module' => 'minify'
				);

				if ( function_exists( 'apcu_store' ) ) {
					$inner_cache = new Cache_Apcu( $config );
				} elseif ( function_exists( 'apc_store' ) ) {
					$inner_cache = new Cache_Apc( $config );
				}
				break;

			case 'eaccelerator':
				$config = array(
					'blog_id' => Util_Environment::blog_id(),
					'instance_id' => Util_Environment::instance_id(),
					'host' =>  Util_Environment::host(),
					'module' => 'minify'
				);
				$inner_cache = new Cache_Eaccelerator( $config );
				break;

			case 'xcache':
				$config = array(
					'blog_id' => Util_Environment::blog_id(),
					'instance_id' => Util_Environment::instance_id(),
					'host' =>  Util_Environment::host(),
					'module' => 'minify'
				);
				$inner_cache = new Cache_Xcache( $config );
				break;

			case 'wincache':
				$config = array(
					'blog_id' => Util_Environment::blog_id(),
					'instance_id' => Util_Environment::instance_id(),
					'host' =>  Util_Environment::host(),
					'module' => 'minify'
				);
				$inner_cache = new Cache_Wincache( $config );
				break;
			}

			if ( !is_null( $inner_cache ) ) {
				$cache = new \W3TCL\Minify\Minify_Cache_W3TCDerived( $inner_cache );
			} else {
				// case 'file' or fallback

				$cache = new \W3TCL\Minify\Minify_Cache_File(
					Util_Environment::cache_blog_minify_dir(),
					array(
						'.htaccess',
						'index.html',
						'*_old'
					),
					$this->_config->get_boolean( 'minify.file.locking' ),
					$this->_config->get_integer( 'timelimit.cache_flush' ),
					( Util_Environment::blog_id() == 0 ? W3TC_CACHE_MINIFY_DIR : null )
				);
			}
		}

		return $cache;
	}

	/**
	 * Handle minify error
	 *
	 * @param string  $error
	 * @return void
	 */
	function _handle_error( $error ) {
		$notification = $this->_config->get_string( 'minify.error.notification' );

		if ( $notification ) {
			$file = Util_Request::get_string( 'file' );
			$state = Dispatcher::config_state_master();

			if ( $file ) {
				$state->set( 'minify.error.file', $file );
			}

			if ( stristr( $notification, 'admin' ) !== false ) {
				$state->set( 'minify.error.last', $error );
				$state->set( 'minify.show_note_minify_error', true );
			}

			if ( stristr( $notification, 'email' ) !== false ) {
				$last = $state->get_integer( 'minify.error.notification.last' );

				/**
				 * Prevent email flood: send email every 5 min
				 */
				if ( ( time() - $last ) > 300 ) {
					$state->set( 'minify.error.notification.last', time() );
					$this->_send_notification();
				}
			}

			$state->save();
		}
	}

	/**
	 * Send E-mail notification when error occurred
	 *
	 * @return boolean
	 */
	function _send_notification() {
		$from_email = 'wordpress@' . Util_Environment::host();
		$from_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		$to_name = $to_email = get_option( 'admin_email' );
		$body = @file_get_contents( W3TC_INC_DIR . '/email/minify_error_notification.php' );

		$headers = array(
			sprintf( 'From: "%s" <%s>', addslashes( $from_name ), $from_email ),
			sprintf( 'Reply-To: "%s" <%s>', addslashes( $to_name ), $to_email ),
			'Content-Type: text/html; charset=utf-8'
		);

		@set_time_limit( $this->_config->get_integer( 'timelimit.email_send' ) );

		$result = @wp_mail( $to_email, 'W3 Total Cache Error Notification', $body, implode( "\n", $headers ) );

		return $result;
	}

	/**
	 * Generates file ID
	 *
	 * @param array   $sources
	 * @param string  $type
	 * @return string
	 */
	function _generate_id( $sources, $type ) {
		$values =array();
		foreach ( $sources as $source )
			if ( is_string( $source ) )
				$values[] = $source;
			else
				$values[] = $source->filepath;
			foreach ( $sources as $source ) {
				if ( is_string( $source ) && file_exists( $source ) ) {
					$data = @file_get_contents( $source );

					if ( $data !== false ) {
						$values[] = md5( $data );
					} else {
						return false;
					}
				} else {
					$headers = @get_headers( $source->minifyOptions['prependRelativePath'] );
					if ( strpos( $headers[0], '200' ) !== false ) {
						$segments = explode( '.', $source->minifyOptions['prependRelativePath'] );
						$ext = strtolower( array_pop( $segments ) );
						$pc_source = $this->_precache_file( $source->minifyOptions['prependRelativePath'], $ext );
						$data = @file_get_contents( $pc_source->filepath );

						if ( $data !== false ) {
							$values[] = md5( $data );
						} else {
							return false;
						}
					}else {
						return false;
					}
				}
			}

		$keys = array(
			'minify.debug',
			'minify.engine',
			'minify.options',
			'minify.symlinks',
		);

		if ( $type == 'js' ) {
			$engine = $this->_config->get_string( 'minify.js.engine' );

			if ( $this->_config->get_boolean( 'minify.auto' ) ) {
				$keys[] = 'minify.js.method';
			} else {
				array_merge(
					$keys,
					array(
						'minify.js.combine.header',
						'minify.js.combine.body',
						'minify.js.combine.footer',
					)
				);
			}

			switch ( $engine ) {
			case 'js':
				$keys = array_merge( $keys, array(
						'minify.js.strip.comments',
						'minify.js.strip.crlf',
					) );
				break;

			case 'yuijs':
				$keys = array_merge( $keys, array(
						'minify.yuijs.options.line-break',
						'minify.yuijs.options.nomunge',
						'minify.yuijs.options.preserve-semi',
						'minify.yuijs.options.disable-optimizations',
					) );
				break;

			case 'ccjs':
				$keys = array_merge( $keys, array(
						'minify.ccjs.options.compilation_level',
						'minify.ccjs.options.formatting',
					) );
				break;
			}
		} elseif ( $type == 'css' ) {
			$engine = $this->_config->get_string( 'minify.css.engine' );
			$keys[] = 'minify.css.method';

			switch ( $engine ) {
			case 'css':
				$keys = array_merge( $keys, array(
						'minify.css.strip.comments',
						'minify.css.strip.crlf',
						'minify.css.imports',
					) );
				break;

			case 'yuicss':
				$keys = array_merge( $keys, array(
						'minify.yuicss.options.line-break',
					) );
				break;

			case 'csstidy':
				$keys = array_merge( $keys, array(
						'minify.csstidy.options.remove_bslash',
						'minify.csstidy.options.compress_colors',
						'minify.csstidy.options.compress_font-weight',
						'minify.csstidy.options.lowercase_s',
						'minify.csstidy.options.optimise_shorthands',
						'minify.csstidy.options.remove_last_;',
						'minify.csstidy.options.remove_space_before_important',
						'minify.csstidy.options.case_properties',
						'minify.csstidy.options.sort_properties',
						'minify.csstidy.options.sort_selectors',
						'minify.csstidy.options.merge_selectors',
						'minify.csstidy.options.discard_invalid_selectors',
						'minify.csstidy.options.discard_invalid_properties',
						'minify.csstidy.options.css_level',
						'minify.csstidy.options.preserve_css',
						'minify.csstidy.options.timestamp',
						'minify.csstidy.options.template',
					) );
				break;
			}
		}

		foreach ( $keys as $key ) {
			$values[] = $this->_config->get( $key );
		}

		$id = substr( md5( implode( '', $this->_flatten_array( $values ) ) ), 0, 6 );

		return $id;
	}

	/**
	 * Takes a multidimensional array and makes it singledimensional
	 *
	 * @param unknown $values
	 * @return array
	 */
	private function _flatten_array( $values ) {
		$flatten = array();

		foreach ( $values as $key => $value ) {
			if ( is_array( $value ) )
				$flatten = array_merge( $flatten, $this->_flatten_array( $value ) );
			else
				$flatten[$key] = $value;
		}
		return $flatten;
	}

	/**
	 * Returns cache data
	 *
	 * @param string  $key
	 * @return bool|array
	 */
	function _cache_get( $key ) {
		$cache = $this->_get_cache();

		$data = $cache->fetch( $key );

		if ( isset( $data['content'] ) ) {
			$value = @unserialize( $data['content'] );

			return $value;
		}

		return false;
	}

	/**
	 * Sets cache date
	 *
	 * @param string  $key
	 * @param string  $value
	 * @return boolean
	 */
	function _cache_set( $key, $value ) {
		$cache = $this->_get_cache();

		return $cache->store( $key, array( 'content' => serialize( $value ) ) );
	}
}
