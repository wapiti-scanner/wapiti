<?php
namespace W3TC;

/**
 * The W3 Total Cache plugin integration
 *
 * @package wp-cli
 * @subpackage commands/third-party
 */
class W3TotalCache_Command extends \WP_CLI_Command {
	/**
	 * Creates missing files, writes apache/nginx rules.
	 *
	 * ## OPTIONS
	 * [<server>]
	 * : Subcommand defines server type:
	 *   apache   create rules for apache server
	 *   nginx    create rules for nginx server
	 */
	function fix_environment( $args = array(), $vars = array() ) {
		$server_type = array_shift( $args );
		switch ( $server_type ) {
		case 'apache':
			$_SERVER['SERVER_SOFTWARE'] = 'Apache';
			break;
		case 'nginx':
			$_SERVER['SERVER_SOFTWARE'] = 'nginx';
			break;
		}

		try {
			$config = Dispatcher::config();
			$environment = Dispatcher::component( 'Root_Environment' );
			$environment->fix_in_wpadmin( $config, true );
		} catch ( Util_Environment_Exceptions $e ) {
			\WP_CLI::error( __( 'Environment adjustment failed with error', 'w3-total-cache' ),
				$e->getCombinedMessage() );
		}

		\WP_CLI::success( __( 'Environment adjusted.', 'w3-total-cache' ) );
	}



	/**
	 * Clear something from the cache.
	 *
	 * ## OPTIONS
	 * <cache>
	 * : Cache to flush
	 * all         flush all caches
	 * posts       flush posts (pagecache and further)
	 * post        flush the page cache
	 * database    flush the database cache
	 * object      flush the object cache
	 * minify      flush the minify cache
	 *
	 * [--post_id=<id>]
	 * : flush a specific post ID
	 *
	 * [--permalink=<post-permalink>]
	 * : flush a specific permalink
	 *
	 * ## EXAMPLES
	 *     # Flush all
	 *     $ wp w3-total-cache flush all
	 *
	 *     # Flush pagecache and reverse proxies
	 *     $ wp w3-total-cache flush posts
	 */
	function flush( $args = array(), $vars = array() ) {
		$args = array_unique( $args );

		do {
			$cache_type = array_shift( $args );

			switch ( $cache_type ) {
			case 'all':
				try {
					w3tc_flush_all();
				}
				catch ( \Exception $e ) {
					\WP_CLI::error( __( 'Flushing all failed.', 'w3-total-cache' ) );
				}
				\WP_CLI::success( __( 'Everything flushed successfully.', 'w3-total-cache' ) );
				break;

			case 'posts':
				try {
					w3tc_flush_posts();
				}
				catch ( \Exception $e ) {
					\WP_CLI::error( __( 'Flushing posts/pages failed.', 'w3-total-cache' ) );
				}
				\WP_CLI::success( __( 'Posts/pages flushed successfully.', 'w3-total-cache' ) );
				break;

			case 'db':
			case 'database':
				try {
					$w3_db = Dispatcher::component( 'CacheFlush' );
					$w3_db->dbcache_flush();
				}
				catch ( \Exception $e ) {
					\WP_CLI::error( __( 'Flushing the DB cache failed.', 'w3-total-cache' ) );
				}
				\WP_CLI::success( __( 'The DB cache is flushed successfully.', 'w3-total-cache' ) );
				break;

			case 'minify':
				try {
					$w3_minify = Dispatcher::component( 'CacheFlush' );
					$w3_minify->minifycache_flush();
				}
				catch ( \Exception $e ) {
					\WP_CLI::error( __( 'Flushing the minify cache failed.', 'w3-total-cache' ) );
				}
				\WP_CLI::success( __( 'The minify cache is flushed successfully.', 'w3-total-cache' ) );
				break;

			case 'object':
				try {
					$w3_objectcache = Dispatcher::component( 'CacheFlush' );
					$w3_objectcache->objectcache_flush();
				}
				catch ( \Exception $e ) {
					\WP_CLI::error( __( 'Flushing the object cache failed.', 'w3-total-cache' ) );
				}
				\WP_CLI::success( __( 'The object cache is flushed successfully.', 'w3-total-cache' ) );
				break;

			case 'post':
				if ( isset( $vars['post_id'] ) ) {
					if ( is_numeric( $vars['post_id'] ) ) {
						try {
							w3tc_flush_post( $vars['post_id'], true );
						}
						catch ( \Exception $e ) {
							\WP_CLI::error( __( 'Flushing the page from cache failed.', 'w3-total-cache' ) );
						}
						\WP_CLI::success( __( 'The page is flushed from cache successfully.', 'w3-total-cache' ) );
					} else {
						\WP_CLI::error( __( 'This is not a valid post id.', 'w3-total-cache' ) );
					}
				}
				elseif ( isset( $vars['permalink'] ) ) {
					try {
						w3tc_flush_url( $vars['permalink'] );
					}
					catch ( \Exception $e ) {
						\WP_CLI::error( __( 'Flushing the page from cache failed.', 'w3-total-cache' ) );
					}
					\WP_CLI::success( __( 'The page is flushed from cache successfully.', 'w3-total-cache' ) );
				} else {
					if ( isset( $flushed_page_cache ) && $flushed_page_cache )
						break;

					try {
						w3tc_flush_posts();
					}
					catch ( \Exception $e ) {
						\WP_CLI::error( __( 'Flushing the page cache failed.', 'w3-total-cache' ) );
					}
					\WP_CLI::success( __( 'The page cache is flushed successfully.', 'w3-total-cache' ) );
				}
				break;

			default:
				\WP_CLI::error( __( 'Not specified what to flush', 'w3-total-cache' ) );
			}
		} while ( !empty( $args ) );
	}

	/**
	 * Get or set option.
	 *
	 * Options modifications don't update your .htaccess automatically.
	 * Use fix_environment command afterwards to do it.
	 *
	 * ## OPTIONS
	 * <operation>
	 * : operation to do
	 * get  get option value
	 * set  set option value
	 * <name>
	 * : option name
	 *
	 * [<value>]
	 * : (for set operation) Value to set
	 *
	 * [--state]
	 * : use state, not config
	 * state is used for backend notifications
	 *
	 * [--master]
	 * : use master config/state
     *
	 * [--type=<type>]
	 * : type of data used boolean/string/integer/array. Default string
	 *
	 * [--delimiter=<delimiter>]
	 * : delimiter to use for array type values
	 *
	 * ## EXAMPLES
	 *     # get if pagecache enabled
	 *     $ wp w3-total-cache option get pgcache.enabled --type=boolean
	 *
	 *     # enable pagecache
	 *     $ wp w3-total-cache option set pgcache.enabled true --type=boolean
	 *
	 *     # don't show wp-content permissions notification
	 *     $ wp w3-total-cache option set common.hide_note_wp_content_permissions true --state --type=boolean
	 */
	function option( $args = array(), $vars = array() ) {
		$op = array_shift( $args );
		$name = array_shift( $args );

		if ( empty( $name ) ) {
			\WP_CLI::error( __( '<name> parameter is not specified', 'w3-total-cache' ) );
			return;
		}
		if ( strpos( $name, '::' ) !== FALSE ) {
			$name = explode('::', $name);
		}

		$c = null;
		if ( isset( $vars['state'] ) ) {
			if ( isset( $vars['master'] ) )
				$c = Dispatcher::config_state_master();
			else
				$c = Dispatcher::config_state();
		} else {
			if ( isset( $vars['master'] ) )
				$c = Dispatcher::config_master();
			else
				$c = Dispatcher::config();
		}

		if ( $op == 'get') {
			$type =( isset( $vars['type'] ) ? $vars['type'] : 'string' );

			if ( $type == 'boolean' )
				$v = $c->get_boolean( $name ) ? 'true' : 'false';
			elseif ( $type == 'integer' )
				$v = $c->get_integer( $name );
			elseif ( $type == 'string' )
				$v = $c->get_string( $name );
			elseif ( $type == 'array' )
				$v = json_encode( $c->get_array( $name ), JSON_PRETTY_PRINT );
			else {
				\WP_CLI::error( __( 'Unknown type ' . $type, 'w3-total-cache' ) );
				return;
			}

			echo esc_html( $v ) . "\n";
		} elseif ( $op == 'set' ) {
			$type =( isset( $vars['type'] ) ? $vars['type'] : 'string' );

			if ( count( $args ) <= 0 ) {
				\WP_CLI::error( __( '<value> parameter is not specified', 'w3-total-cache' ) );
				return;
			}
			$value = array_shift( $args );

			if ( $type == 'boolean' ) {
				if ( $value == 'true' || $value == '1' || $value == 'on' )
					$v = true;
				elseif ( $value == 'false' || $value == '0' || $value == 'off' )
					$v = false;
				else {
					\WP_CLI::error( __( '<value> parameter ' . $value . ' is not boolean', 'w3-total-cache' ) );
					return;
				}
			} elseif ( $type == 'integer' )
				$v = (integer)$value;
			elseif ( $type == 'string' )
				$v = $value;
			elseif ( $type == 'array' ) {
				$delimiter =( isset( $vars['delimiter'] ) ? $vars['delimiter'] : ',' );
				$v = explode($delimiter, $value );
			} else {
				\WP_CLI::error( __( 'Unknown type ' . $type, 'w3-total-cache' ) );
				return;
			}

			try {
				$c->set( $name, $v );
				$c->save();
				\WP_CLI::success( __( 'Option updated successfully.', 'w3-total-cache' ) );
			} catch ( \Exception $e ) {
				\WP_CLI::error( __( 'Option value update failed.', 'w3-total-cache' ) );
			}

		} else {
			\WP_CLI::error( __( '<operation> parameter is not specified', 'w3-total-cache' ) );
		}
	}

	/**
	 * Imports configuration file
	 *
	 * ## OPTIONS
	 * <filename>
	 * : Filename to import
	 */
	function import( $args = array(), $vars = array() ) {
		$filename = array_shift( $args );

		try {
			$config = new Config();
			if ( !file_exists( $filename ) || !is_readable( $filename ) ) {
				throw new \Exception( 'Cant read file: ' . $filename );
			}
			if ( !$config->import( $filename ) ) {
				throw new \Exception( 'import failed' );
			}
			$config->save();
		} catch ( \Exception $e ) {
			\WP_CLI::error( __( 'Config import failed: ' . $e->getMessage(), 'w3-total-cache' ) );
		}

		\WP_CLI::success( __( 'Configuration successfully imported.', 'w3-total-cache' ) );
	}

	/**
	 * Update query string for all static files
	 */
	function querystring() {
		try {
			$w3_querystring = Dispatcher::component( 'CacheFlush' );
			$w3_querystring->browsercache_flush();
		}
		catch ( \Exception $e ) {
			\WP_CLI::error( sprintf(
					__( 'updating the query string failed. with error %s', 'w3-total-cache' ),
					$e ) );
		}

		\WP_CLI::success( __( 'The query string was updated successfully.', 'w3-total-cache' ) );

	}

	/**
	 * Purges URL's from cdn and varnish if enabled
	 *
	 * @param array $args List if files to be purged, absolute path or relative to wordpress installation path
	 */
	function cdn_purge( $args = array() ) {
		$purgeitems = array();
		foreach ( $args as $file ) {
			$cdncommon = Dispatcher::component( 'Cdn_Core' );
			if (file_exists($file)) {
				$local_path = $file;
			} else {
				$local_path = ABSPATH . $file;
			}
			$remote_path = $file;
			$purgeitems[] = $cdncommon->build_file_descriptor( $local_path, $remote_path );
		}

		try {
			$w3_cdn_purge = Dispatcher::component( 'CacheFlush' );
			$w3_cdn_purge->cdn_purge_files( $purgeitems );
		}
		catch ( \Exception $e ) {
			\WP_CLI::error( __( 'Files did not successfully purge with error %s', 'w3-total-cache' ), $e );
		}
		\WP_CLI::success( __( 'Files purged successfully.', 'w3-total-cache' ) );

	}

	/**
	 * Generally triggered from a cronjob, performs manual page cache Garbage collection
	 */
	function pgcache_cleanup() {
		try {
			$o = Dispatcher::component( 'PgCache_Plugin_Admin' );
			$o->cleanup();
		} catch ( \Exception $e ) {
			\WP_CLI::error( __( 'PageCache Garbage cleanup failed: %s',
				'w3-total-cache' ), $e );
		}

		\WP_CLI::success( __( 'PageCache Garbage cleanup triggered successfully.',
			'w3-total-cache' ) );
	}



	/**
	 * Generally triggered from a cronjob, performs manual page cache priming
	 * ## OPTIONS
	 * [--start=<start>]
	 * : Start since <start> entry of sitemap
	 *
	 * [--limit=<limit>]
	 * : load no more than <limit> pages
	 *
	 */
	function pgcache_prime( $args = array(), $vars = array() ) {
		try {
			$log_callback = function($m) {
				\WP_CLI::log($m);
			};

			$o = Dispatcher::component( 'PgCache_Plugin_Admin' );
			$o->prime( ( isset( $vars['start'] ) ? $vars['start'] - 1 : null ),
				( isset( $vars['limit'] ) ? $vars['limit'] : null ),
				$log_callback );

		} catch ( \Exception $e ) {
			\WP_CLI::error( __( 'PageCache Priming did failed: %s',
				'w3-total-cache' ), $e );
		}

		\WP_CLI::success( __( 'PageCache Priming triggered successfully.',
			'w3-total-cache' ) );
	}
}



if ( method_exists( '\WP_CLI', 'add_command' ) ) {
	\WP_CLI::add_command( 'w3-total-cache', '\W3TC\W3TotalCache_Command' );
	\WP_CLI::add_command( 'total-cache', '\W3TC\W3TotalCache_Command' );
} else {
	// backward compatibility
	\WP_CLI::addCommand( 'w3-total-cache', '\W3TC\W3TotalCache_Command' );
	\WP_CLI::addCommand( 'total-cache', '\W3TC\W3TotalCache_Command' );
}
