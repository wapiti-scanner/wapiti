<?php
/**
 * File: SetupGuide_Plugin_Admin.php
 *
 * @since 2.0.0
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: SetupGuide_Plugin_Admin
 *
 * @since 2.0.0
 */
class SetupGuide_Plugin_Admin {
	/**
	 * Current page.
	 *
	 * @since  2.0.0
	 * @access protected
	 *
	 * @var string
	 */
	protected $_page = 'w3tc_setup_guide'; // phpcs:ignore PSR2.Classes.PropertyDeclaration.Underscore

	/**
	 * Wizard template.
	 *
	 * @var \W3TC\Wizard\Template
	 */
	private static $template;

	/**
	 * Constructor.
	 *
	 * @since 2.0.0
	 */
	public function __construct() {
		$page         = Util_Request::get_string( 'page' );
		$is_w3tc_ajax = defined( 'DOING_AJAX' ) && DOING_AJAX &&
			! empty( Util_Request::get_string( 'action' ) )
			&& 0 === strpos( Util_Request::get_string( 'action' ), 'w3tc_' );

		if ( 'w3tc_setup_guide' === $page || $is_w3tc_ajax ) {
			require_once W3TC_INC_DIR . '/wizard/template.php';

			if ( is_null( self::$template ) ) {
				self::$template = new Wizard\Template( $this->get_config() );
			}
		}
	}

	/**
	 * Run.
	 *
	 * Needed by the Root_Loader.
	 *
	 * @since 2.0.0
	 */
	public function run() {
	}

	/**
	 * Display the setup guide.
	 *
	 * @since 2.0.0
	 *
	 * @see \W3TC\Wizard\Template::render()
	 */
	public function load() {
		self::$template->render();
	}

	/**
	 * Admin-Ajax: Set option to skip the setup guide.
	 *
	 * @since 2.0.0
	 */
	public function skip() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			update_site_option( 'w3tc_setupguide_completed', time() );
			wp_send_json_success();
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Set the terms of service choice.
	 *
	 * @since 2.0.0
	 *
	 * @uses $_POST['choice'] TOS choice: accept/decline.
	 */
	public function set_tos_choice() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$choice          = Util_Request::get_string( 'choice' );
			$allowed_choices = array(
				'accept',
				'decline',
			);

			if ( in_array( $choice, $allowed_choices, true ) ) {
				$config = new Config();

				if ( ! Util_Environment::is_w3tc_pro( $config ) ) {
					$state_master = Dispatcher::config_state_master();
					$state_master->set( 'license.community_terms', $choice );
					$state_master->save();

					$config->set( 'common.track_usage', ( 'accept' === $choice ) );
					$config->save();
				}

				wp_send_json_success();
			} else {
				wp_send_json_error( __( 'Invalid choice', 'w3-total-cache' ), 400 );
			}
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Abbreviate a URL for display in a small space.
	 *
	 * @since 2.0.0
	 *
	 * @param  string $url URL.
	 * @return string
	 */
	public function abbreviate_url( $url ) {
		$url = untrailingslashit(
			str_replace(
				array(
					'https://',
					'http://',
					'www.',
				),
				'',
				$url
			)
		);

		if ( strlen( $url ) > 35 ) {
			$url = substr( $url, 0, 10 ) . '&hellip;' . substr( $url, -20 );
		}

		return $url;
	}

	/**
	 * Admin-Ajax: Test Page Cache.
	 *
	 * @since  2.0.0
	 *
	 * @see self::abbreviate_url()
	 * @see \W3TC\Util_Http::ttfb()
	 */
	public function test_pgcache() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$nocache = ! empty( Util_Request::get_string( 'nocache' ) );
			$url     = site_url();
			$results = array(
				'nocache'  => $nocache,
				'url'      => $url,
				'urlshort' => $this->abbreviate_url( $url ),
			);

			if ( ! $nocache ) {
				Util_Http::get( $url, array( 'user-agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' ) ) );
			}

			$results['ttfb'] = Util_Http::ttfb( $url, $nocache );

			wp_send_json_success( $results );
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Get the page cache settings.
	 *
	 * @since  2.0.0
	 *
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::get_string()
	 */
	public function get_pgcache_settings() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$config = new Config();

			wp_send_json_success(
				array(
					'enabled' => $config->get_boolean( 'pgcache.enabled' ),
					'engine'  => $config->get_string( 'pgcache.engine' ),
				)
			);
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Configure the page cache settings.
	 *
	 * @since  2.0.0
	 *
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::get_string()
	 * @see \W3TC\Util_Installed::$engine()
	 * @see \W3TC\Config::set()
	 * @see \W3TC\Config::save()
	 * @see \W3TC\Dispatcher::component()
	 * @see \W3TC\CacheFlush::flush_posts()
	 */
	public function config_pgcache() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$enable          = ! empty( Util_Request::get_string( 'enable' ) );
			$engine          = empty( Util_Request::get_string( 'engine' ) ) ? '' : esc_attr( Util_Request::get_string( 'engine', '', true ) );
			$is_updating     = false;
			$success         = false;
			$config          = new Config();
			$pgcache_enabled = $config->get_boolean( 'pgcache.enabled' );
			$pgcache_engine  = $config->get_string( 'pgcache.engine' );
			$allowed_engines = array(
				'',
				'file',
				'file_generic',
				'redis',
				'memcached',
				'nginx_memcached',
				'apc',
				'eaccelerator',
				'xcache',
				'wincache',
			);

			if ( in_array( $engine, $allowed_engines, true ) ) {
				if ( empty( $engine ) || 'file' === $engine || 'file_generic' === $engine || Util_Installed::$engine() ) {
					if ( $pgcache_enabled !== $enable ) {
						$config->set( 'pgcache.enabled', $enable );
						$is_updating = true;
					}

					if ( ! empty( $engine ) && $pgcache_engine !== $engine ) {
						$config->set( 'pgcache.engine', $engine );
						$is_updating = true;
					}

					if ( $is_updating ) {
						$config->save();

						$f = Dispatcher::component( 'CacheFlush' );
						$f->flush_posts();

						$e = Dispatcher::component( 'PgCache_Environment' );
						$e->fix_on_wpadmin_request( $config, true );
					}

					if ( $config->get_boolean( 'pgcache.enabled' ) === $enable &&
						( ! $enable || $config->get_string( 'pgcache.engine' ) === $engine ) ) {
							$success = true;
							$message = __( 'Settings updated', 'w3-total-cache' );
					} else {
						$message = __( 'Settings not updated', 'w3-total-cache' );
					}
				} else {
					$message = __( 'Requested cache storage engine is not available', 'w3-total-cache' );
				}
			} elseif ( ! $is_allowed_engine ) {
				$message = __( 'Requested cache storage engine is invalid', 'w3-total-cache' );
			}

			wp_send_json_success(
				array(
					'success'          => $success,
					'message'          => $message,
					'enable'           => $enable,
					'engine'           => $engine,
					'current_enabled'  => $config->get_boolean( 'pgcache.enabled' ),
					'current_engine'   => $config->get_string( 'pgcache.engine' ),
					'previous_enabled' => $pgcache_enabled,
					'previous_engine'  => $pgcache_engine,
				)
			);
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Test database cache.
	 *
	 * @since 2.0.0
	 *
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::get_string()
	 *
	 * @global $wpdb WordPress database object.
	 */
	public function test_dbcache() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$config  = new Config();
			$results = array(
				'enabled' => $config->get_boolean( 'dbcache.enabled' ),
				'engine'  => $config->get_string( 'dbcache.engine' ),
				'elapsed' => null,
			);

			global $wpdb;

			$wpdb->flush();

			$start_time = microtime( true );
			$wpdb->timer_start();

			// Test insert, get, and delete 200 records.
			$table  = $wpdb->prefix . 'options';
			$option = 'w3tc_test_dbcache_';

			// phpcs:disable WordPress.DB.DirectDatabaseQuery

			for ( $x = 0; $x < 200; $x++ ) {
				$wpdb->insert(
					$table,
					array(
						'option_name'  => $option . $x,
						'option_value' => 'blah',
					)
				);

				/*
				 * @see https://developer.wordpress.org/reference/classes/wpdb/prepare/
				 * I had to use %1$s as the method does not encapsulate the value with quotes,
				 * which would be a syntax error.
				 */
				$select = $wpdb->prepare(
					'SELECT `option_value` FROM `%1$s` WHERE `option_name` = %s AND `option_name` NOT LIKE %s', // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnquotedComplexPlaceholder
					$table,
					$option . $x,
					'NotAnOption'
				);

				$wpdb->get_var( $select ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

				$wpdb->get_var( $select ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

				$wpdb->update(
					$table,
					array( 'option_name' => $option . $x ),
					array( 'option_value' => 'This is a dummy test.' )
				);

				$wpdb->delete( $table, array( 'option_name' => $option . $x ) );
			}

			// phpcs:enable WordPress.DB.DirectDatabaseQuery

			$results['wpdb_time'] = $wpdb->timer_stop();
			$results['exec_time'] = microtime( true ) - $start_time;
			$results['elapsed']   = $results['wpdb_time'];

			wp_send_json_success( $results );
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Get the database cache settings.
	 *
	 * @since  2.0.0
	 *
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::get_string()
	 */
	public function get_dbcache_settings() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$config = new Config();

			wp_send_json_success(
				array(
					'enabled' => $config->get_boolean( 'dbcache.enabled' ),
					'engine'  => $config->get_string( 'dbcache.engine' ),
				)
			);
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Configure the database cache settings.
	 *
	 * @since  2.0.0
	 *
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::get_string()
	 * @see \W3TC\Util_Installed::$engine()
	 * @see \W3TC\Config::set()
	 * @see \W3TC\Config::save()
	 * @see \W3TC\Dispatcher::component()
	 * @see \W3TC\CacheFlush::dbcache_flush()
	 */
	public function config_dbcache() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$enable          = ! empty( Util_Request::get_string( 'enable' ) );
			$engine          = empty( Util_Request::get_string( 'engine' ) ) ? '' : esc_attr( Util_Request::get_string( 'engine', '', true ) );
			$is_updating     = false;
			$success         = false;
			$config          = new Config();
			$old_enabled     = $config->get_boolean( 'dbcache.enabled' );
			$old_engine      = $config->get_string( 'dbcache.engine' );
			$allowed_engines = array(
				'',
				'file',
				'redis',
				'memcached',
				'apc',
				'eaccelerator',
				'xcache',
				'wincache',
			);

			if ( in_array( $engine, $allowed_engines, true ) ) {
				if ( empty( $engine ) || 'file' === $engine || Util_Installed::$engine() ) {
					if ( $old_enabled !== $enable ) {
						$config->set( 'dbcache.enabled', $enable );
						$is_updating = true;
					}

					if ( ! empty( $engine ) && $old_engine !== $engine ) {
						$config->set( 'dbcache.engine', $engine );
						$is_updating = true;
					}

					if ( $is_updating ) {
						$config->save();

						$f = Dispatcher::component( 'CacheFlush' );
						$f->dbcache_flush();
					}

					if ( $config->get_boolean( 'dbcache.enabled' ) === $enable &&
						( ! $enable || $config->get_string( 'dbcache.engine' ) === $engine ) ) {
							$success = true;
							$message = __( 'Settings updated', 'w3-total-cache' );
					} else {
						$message = __( 'Settings not updated', 'w3-total-cache' );
					}
				} else {
					$message = __( 'Requested cache storage engine is not available', 'w3-total-cache' );
				}
			} elseif ( ! $is_allowed_engine ) {
				$message = __( 'Requested cache storage engine is invalid', 'w3-total-cache' );
			}

			wp_send_json_success(
				array(
					'success'          => $success,
					'message'          => $message,
					'enable'           => $enable,
					'engine'           => $engine,
					'current_enabled'  => $config->get_boolean( 'dbcache.enabled' ),
					'current_engine'   => $config->get_string( 'dbcache.engine' ),
					'previous_enabled' => $old_enabled,
					'previous_engine'  => $old_engine,
				)
			);
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Test object cache.
	 *
	 * @since 2.0.0
	 *
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::get_string()
	 */
	public function test_objcache() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$config  = new Config();
			$results = array(
				'enabled' => $config->get_boolean( 'objectcache.enabled' ),
				'engine'  => $config->get_string( 'objectcache.engine' ),
				'elapsed' => null,
			);

			$start_time = microtime( true );

			$posts = get_posts(
				array(
					'post_type' => array(
						'page',
						'post',
					),
				)
			);

			$results['elapsed'] = microtime( true ) - $start_time;
			$results['post_ct'] = count( $posts );

			wp_send_json_success( $results );
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Get the object cache settings.
	 *
	 * @since  2.0.0
	 *
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::get_string()
	 */
	public function get_objcache_settings() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$config = new Config();

			wp_send_json_success(
				array(
					'enabled' => $config->get_boolean( 'objectcache.enabled' ),
					'engine'  => $config->get_string( 'objectcache.engine' ),
				)
			);
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Configure the object cache settings.
	 *
	 * @since  2.0.0
	 *
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::get_string()
	 * @see \W3TC\Util_Installed::$engine()
	 * @see \W3TC\Config::set()
	 * @see \W3TC\Config::save()
	 * @see \W3TC\Dispatcher::component()
	 * @see \W3TC\CacheFlush::objcache_flush()
	 */
	public function config_objcache() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$enable          = ! empty( Util_Request::get_string( 'enable' ) );
			$engine          = empty( Util_Request::get_string( 'engine' ) ) ? '' : esc_attr( Util_Request::get_string( 'engine', '', true ) );
			$is_updating     = false;
			$success         = false;
			$config          = new Config();
			$old_enabled     = $config->get_boolean( 'objectcache.enabled' );
			$old_engine      = $config->get_string( 'objectcache.engine' );
			$allowed_engines = array(
				'',
				'file',
				'redis',
				'memcached',
				'apc',
				'eaccelerator',
				'xcache',
				'wincache',
			);

			if ( in_array( $engine, $allowed_engines, true ) ) {
				if ( empty( $engine ) || 'file' === $engine || Util_Installed::$engine() ) {
					if ( $old_enabled !== $enable ) {
						$config->set( 'objectcache.enabled', $enable );
						$is_updating = true;
					}

					if ( ! empty( $engine ) && $old_engine !== $engine ) {
						$config->set( 'objectcache.engine', $engine );
						$is_updating = true;
					}

					if ( $is_updating ) {
						$config->save();

						$f = Dispatcher::component( 'CacheFlush' );
						$f->objectcache_flush();
					}

					if ( $config->get_boolean( 'objectcache.enabled' ) === $enable &&
						( ! $enable || $config->get_string( 'objectcache.engine' ) === $engine ) ) {
							$success = true;
							$message = __( 'Settings updated', 'w3-total-cache' );
					} else {
						$message = __( 'Settings not updated', 'w3-total-cache' );
					}
				} else {
					$message = __( 'Requested cache storage engine is not available', 'w3-total-cache' );
				}
			} elseif ( ! $is_allowed_engine ) {
				$message = __( 'Requested cache storage engine is invalid', 'w3-total-cache' );
			}

			wp_send_json_success(
				array(
					'success'          => $success,
					'message'          => $message,
					'enable'           => $enable,
					'engine'           => $engine,
					'current_enabled'  => $config->get_boolean( 'objectcache.enabled' ),
					'current_engine'   => $config->get_string( 'objectcache.engine' ),
					'previous_enabled' => $old_enabled,
					'previous_engine'  => $old_engine,
				)
			);
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Test URL addreses for Browser Cache header.
	 *
	 * @since  2.0.0
	 *
	 * @see \W3TC\CacheFlush::browsercache_flush()
	 * @see \W3TC\Util_Http::get_headers()
	 */
	public function test_browsercache() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$results = array();
			$urls    = array(
				trailingslashit( site_url() ),
				esc_url( plugin_dir_url( __FILE__ ) . 'pub/css/setup-guide.css' ),
				esc_url( plugin_dir_url( __FILE__ ) . 'pub/js/setup-guide.js' ),
			);

			$f = Dispatcher::component( 'CacheFlush' );
			$f->browsercache_flush();

			$header_missing = esc_html__( 'Not present', 'w3-total-cache' );

			foreach ( $urls as $url ) {
				$headers = Util_Http::get_headers( $url );

				$results[] = array(
					'url'      => $url,
					'filename' => basename( $url ),
					'header'   => empty( $headers['cache-control'] ) ? $header_missing : $headers['cache-control'],
					'headers'  => empty( $headers ) || ! is_array( $headers ) ? array() : $headers,
				);
			}

			wp_send_json_success( $results );
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Get the browser cache settings.
	 *
	 * @since  2.0.0
	 *
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::get_string()
	 */
	public function get_browsercache_settings() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$config = new Config();

			wp_send_json_success(
				array(
					'enabled'             => $config->get_boolean( 'browsercache.enabled' ),
					'cssjs.cache.control' => $config->get_boolean( 'browsercache.cssjs.cache.control' ),
					'cssjs.cache.policy'  => $config->get_string( 'browsercache.cssjs.cache.policy' ),
					'html.cache.control'  => $config->get_boolean( 'browsercache.html.cache.control' ),
					'html.cache.policy'   => $config->get_string( 'browsercache.html.cache.policy' ),
					'other.cache.control' => $config->get_boolean( 'browsercache.other.cache.control' ),
					'other.cache.policy'  => $config->get_string( 'browsercache.other.cache.policy' ),
				)
			);
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Configure the browser cache settings.
	 *
	 * @since  2.0.0
	 *
	 * @see \W3TC\Dispatcher::component()
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::set()
	 * @see \W3TC\Config::save()
	 * @see \W3TC\CacheFlush::browsercache_flush()
	 * @see \W3TC\BrowserCache_Environment::fix_on_wpadmin_request()
	 *
	 * @uses $_POST['enable']
	 */
	public function config_browsercache() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$enable               = ! empty( Util_Request::get_string( 'enable' ) );
			$config               = new Config();
			$browsercache_enabled = $config->get_boolean( 'browsercache.enabled' );

			if ( $browsercache_enabled !== $enable ) {
				$config->set( 'browsercache.enabled', $enable );
				$config->set( 'browsercache.cssjs.cache.control', true );
				$config->set( 'browsercache.cssjs.cache.policy', 'cache_public_maxage' );
				$config->set( 'browsercache.html.cache.control', true );
				$config->set( 'browsercache.html.cache.policy', 'cache_public_maxage' );
				$config->set( 'browsercache.other.cache.control', true );
				$config->set( 'browsercache.other.cache.policy', 'cache_public_maxage' );
				$config->save();

				$f = Dispatcher::component( 'CacheFlush' );
				$f->browsercache_flush();

				$e = Dispatcher::component( 'BrowserCache_Environment' );
				$e->fix_on_wpadmin_request( $config, true );
			}

			$is_enabled = $config->get_boolean( 'browsercache.enabled' );

			wp_send_json_success(
				array(
					'success'               => $is_enabled === $enable,
					'enable'                => $enable,
					'browsercache_enabled'  => $config->get_boolean( 'browsercache.enabled' ),
					'browsercache_previous' => $browsercache_enabled,
				)
			);
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Get the lazy load settings.
	 *
	 * @since  2.0.0
	 *
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::get_string()
	 * @see \W3TC\Config::get_array()
	 */
	public function get_lazyload_settings() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$config = new Config();

			wp_send_json_success(
				array(
					'enabled'            => $config->get_boolean( 'lazyload.enabled' ),
					'process_img'        => $config->get_boolean( 'lazyload.process_img' ),
					'process_background' => $config->get_boolean( 'lazyload_process_background' ),
					'exclude'            => $config->get_array( 'lazyload.exclude' ),
					'embed_method'       => $config->get_string( 'lazyload.embed_method' ),
				)
			);
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Admin-Ajax: Configure lazy load.
	 *
	 * @since 2.0.0
	 *
	 * @see \W3TC\Dispatcher::component()
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Config::set()
	 * @see \W3TC\Config::save()
	 * @see \W3TC\Dispatcher::component()
	 * @see \W3TC\CacheFlush::flush_posts()
	 *
	 * @uses $_POST['enable']
	 */
	public function config_lazyload() {
		if ( wp_verify_nonce( Util_Request::get_string( '_wpnonce' ), 'w3tc_wizard' ) ) {
			$enable           = ! empty( Util_Request::get_string( 'enable' ) );
			$config           = new Config();
			$lazyload_enabled = $config->get_boolean( 'lazyload.enabled' );

			if ( $lazyload_enabled !== $enable ) {
				$config->set( 'lazyload.enabled', $enable );
				$config->set( 'lazyload.process_img', true );
				$config->set( 'lazyload_process_background', true );
				$config->set( 'lazyload.embed_method', 'async_head' );
				$config->save();

				$f = Dispatcher::component( 'CacheFlush' );
				$f->flush_posts();

				$e = Dispatcher::component( 'PgCache_Environment' );
				$e->fix_on_wpadmin_request( $config, true );
			}

			$is_enabled = $config->get_boolean( 'lazyload.enabled' );

			wp_send_json_success(
				array(
					'success'           => $is_enabled === $enable,
					'enable'            => $enable,
					'lazyload_enabled'  => $config->get_boolean( 'lazyload.enabled' ),
					'lazyload_previous' => $lazyload_enabled,
				)
			);
		} else {
			wp_send_json_error( __( 'Security violation', 'w3-total-cache' ), 403 );
		}
	}

	/**
	 * Display the terms of service dialog if needed.
	 *
	 * @since  2.0.0
	 * @access private
	 *
	 * @see Licensing_Core::get_tos_choice()
	 *
	 * @return bool
	 */
	private function maybe_ask_tos() {
		if ( defined( 'W3TC_PRO' ) ) {
			return false;
		}

		$terms = Licensing_Core::get_tos_choice();

		return 'accept' !== $terms && 'decline' !== $terms && 'postpone' !== $terms;
	}

	/**
	 * Get configuration.
	 *
	 * @since  2.0.0
	 * @access private
	 *
	 * @global $wp_version WordPress version string.
	 * @global $wpdb       WordPress database connection.
	 *
	 * @see \W3TC\Config::get_boolean()
	 * @see \W3TC\Util_Request::get_string()
	 * @see \W3TC\Dispatcher::config_state()
	 * @see \W3TC\Licensing_Core::get_tos_choice()
	 * @see \W3TC\Util_Environment::home_url_host()
	 * @see \W3TC\Util_Environment::w3tc_edition()
	 * @see \W3TC\Util_Widget::list_widgets()
	 *
	 * @return array
	 */
	private function get_config() {
		global $wp_version, $wpdb;

		$config               = new Config();
		$browsercache_enabled = $config->get_boolean( 'browsercache.enabled' );
		$page                 = Util_Request::get_string( 'page' );
		$state                = Dispatcher::config_state();
		$force_master_config  = $config->get_boolean( 'common.force_master' );

		if ( 'w3tc_extensions' === $page ) {
			$page = 'extensions/' . Util_Request::get_string( 'extension' );
		}

		return array(
			'title'          => esc_html__( 'Setup Guide', 'w3-total-cache' ),
			'scripts'        => array(
				array(
					'handle'    => 'setup-guide',
					'src'       => esc_url( plugin_dir_url( __FILE__ ) . 'pub/js/setup-guide.js' ),
					'deps'      => array( 'jquery' ),
					'version'   => W3TC_VERSION,
					'in_footer' => false,
					'localize'  => array(
						'object_name' => 'W3TC_SetupGuide',
						'data'        => array(
							'page'              => $page,
							'wp_version'        => $wp_version,
							'php_version'       => phpversion(),
							'w3tc_version'      => W3TC_VERSION,
							'server_software'   => isset( $_SERVER['SERVER_SOFTWARE'] ) ?
								sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : null,
							'db_version'        => $wpdb->db_version(),
							'home_url_host'     => Util_Environment::home_url_host(),
							'install_version'   => esc_attr( $state->get_string( 'common.install_version' ) ),
							'w3tc_edition'      => esc_attr( Util_Environment::w3tc_edition( $config ) ),
							'list_widgets'      => esc_attr( Util_Widget::list_widgets() ),
							'ga_profile'        => ( defined( 'W3TC_DEBUG' ) && W3TC_DEBUG ) ? 'UA-2264433-7' : 'UA-2264433-8',
							'tos_choice'        => Licensing_Core::get_tos_choice(),
							'track_usage'       => $config->get_boolean( 'common.track_usage' ),
							'test_complete_msg' => __(
								'Testing complete.  Click Next to advance to the section and see the results.',
								'w3-total-cache'
							),
							'test_error_msg'    => __(
								'Could not perform this test.  Please reload the page to try again or click skip button to abort the setup guide.',
								'w3-total-cache'
							),
							'config_error_msg'  => __(
								'Could not update configuration.  Please reload the page to try again or click skip button to abort the setup guide.',
								'w3-total-cache'
							),
							'unavailable_text'  => __( 'Unavailable', 'w3-total-cache' ),
							'none'              => __( 'None', 'w3-total-cache' ),
							'disk'              => __( 'Disk', 'w3-total-cache' ),
							'disk_basic'        => __( 'Disk: Basic', 'w3-total-cache' ),
							'disk_enhanced'     => __( 'Disk: Enhanced', 'w3-total-cache' ),
							'enabled'           => __( 'Enabled', 'w3-total-cache' ),
							'notEnabled'        => __( 'Not Enabled', 'w3-total-cache' ),
							'dashboardUrl'      => esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_dashboard' ) ),
						),
					),
				),
			),
			'styles'         => array(
				array(
					'handle'  => 'setup-guide',
					'src'     => esc_url( plugin_dir_url( __FILE__ ) . 'pub/css/setup-guide.css' ),
					'version' => W3TC_VERSION,
				),
			),
			'actions'        => array(
				array(
					'tag'      => 'wp_ajax_w3tc_wizard_skip',
					'function' => array(
						$this,
						'skip',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_tos_choice',
					'function' => array(
						$this,
						'set_tos_choice',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_get_pgcache_settings',
					'function' => array(
						$this,
						'get_pgcache_settings',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_test_pgcache',
					'function' => array(
						$this,
						'test_pgcache',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_config_pgcache',
					'function' => array(
						$this,
						'config_pgcache',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_get_dbcache_settings',
					'function' => array(
						$this,
						'get_dbcache_settings',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_test_dbcache',
					'function' => array(
						$this,
						'test_dbcache',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_config_dbcache',
					'function' => array(
						$this,
						'config_dbcache',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_get_objcache_settings',
					'function' => array(
						$this,
						'get_objcache_settings',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_test_objcache',
					'function' => array(
						$this,
						'test_objcache',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_config_objcache',
					'function' => array(
						$this,
						'config_objcache',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_get_browsercache_settings',
					'function' => array(
						$this,
						'get_browsercache_settings',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_test_browsercache',
					'function' => array(
						$this,
						'test_browsercache',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_config_browsercache',
					'function' => array(
						$this,
						'config_browsercache',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_get_lazyload_settings',
					'function' => array(
						$this,
						'get_lazyload_settings',
					),
				),
				array(
					'tag'      => 'wp_ajax_w3tc_config_lazyload',
					'function' => array(
						$this,
						'config_lazyload',
					),
				),
			),
			'steps_location' => 'left',
			'steps'          => array(
				array(
					'id'   => 'welcome',
					'text' => __( 'Welcome', 'w3-total-cache' ),
				),
				array(
					'id'   => 'pgcache',
					'text' => __( 'Page Cache', 'w3-total-cache' ),
				),
				array(
					'id'   => 'dbcache',
					'text' => __( 'Database Cache', 'w3-total-cache' ),
				),
				array(
					'id'   => 'objectcache',
					'text' => __( 'Object Cache', 'w3-total-cache' ),
				),
				array(
					'id'   => 'browsercache',
					'text' => __( 'Browser Cache', 'w3-total-cache' ),
				),
				array(
					'id'   => 'lazyload',
					'text' => __( 'Lazy Load', 'w3-total-cache' ),
				),
				array(
					'id'   => 'more',
					'text' => __( 'More Caching Options', 'w3-total-cache' ),
				),
			),
			'slides'         => array(
				array( // Welcome.
					'headline' => __( 'Welcome to the W3 Total Cache Setup Guide!', 'w3-total-cache' ),
					'id'       => 'welcome',
					'markup'   => '<div id="w3tc-welcome"' . ( $this->maybe_ask_tos() ? ' class="hidden"' : '' ) . '>
						<p>' .
						esc_html__(
							'You have selected the Performance Suite that professionals have consistently ranked #1 for options and speed improvements.',
							'w3-total-cache'
						) . '</p>
						<p><strong>' . esc_html__( 'W3 Total Cache', 'w3-total-cache' ) . '</strong>
						' . esc_html__(
							'provides many options to help your website perform faster.  While the ideal settings vary for every website, there are a few settings we recommend that you enable now.',
							'w3-total-cache'
						) . '</p>
						' .
						sprintf(
							// translators: 1: Anchor/link open tag, 2: Anchor/link close tag.
							esc_html__(
								'If you prefer to configure the settings on your own, you can %1$sskip this setup guide%2$s.',
								'w3-total-cache'
							),
							'<a id="w3tc-wizard-skip-link" href="#">',
							'</a>'
						) . '</p>
						</div>' . ( $this->maybe_ask_tos() ?
						'<div id="w3tc-licensing-terms" class="notice notice-info inline">
						<p>' .
						sprintf(
							// translators: 1: Anchor/link open tag, 2: Anchor/link close tag.
							esc_html__(
								'By allowing us to collect data about how W3 Total Cache is used, we can improve our features and experience for everyone. This data will not include any personally identifiable information.  Feel free to review our %1$sterms of use and privacy policy%2$s.',
								'w3-total-cache'
							),
							'<a target="_blank" href="' . esc_url( 'https://api.w3-edge.com/v1/redirects/policies-terms' ) . '">',
							'</a>'
						) . '</p>
						<p>
						<input type="button" class="button" data-choice="accept" value="' . esc_html__( 'Accept', 'w3-total-cache' ) . '" /> &nbsp;
						<input type="button" class="button" data-choice="decline" value="' . esc_html__( 'Decline', 'w3-total-cache' ) . '" />
						</p>
						</div>' : '' ),
				),
				array( // Page Cache.
					'headline' => __( 'Page Cache', 'w3-total-cache' ),
					'id'       => 'pc1',
					'markup'   => '<p>' . sprintf(
						// translators: 1: HTML emphesis open tag, 2: HTML emphesis close tag.
						esc_html__(
							'The time it takes between a visitor\'s browser page request and receiving the first byte of a response is referred to as %1$sTime to First Byte%2$s.',
							'w3-total-cache'
						),
						'<em>',
						'</em>'
					) . '</p>
					<p>
						<strong>' . esc_html__( 'W3 Total Cache', 'w3-total-cache' ) . '</strong> ' .
						esc_html__( 'can help you speed up', 'w3-total-cache' ) .
						' <em>' . esc_html__( 'Time to First Byte', 'w3-total-cache' ) . '</em> by using Page Cache.
					</p>
					<p>' .
					esc_html__(
						'We\'ll test your homepage with Page Cache disabled and then with several storage engines.  You should review the test results and choose the best for your website.',
						'w3-total-cache'
					) . '</p>
					<p>
						<input id="w3tc-test-pgcache" class="button-primary" type="button" value="' .
						esc_html__( 'Test Page Cache', 'w3-total-cache' ) . '">
						<span class="hidden"><span class="spinner inline"></span>' . esc_html__( 'Measuring', 'w3-total-cache' ) .
						' <em>' . esc_html__( 'Time to First Byte', 'w3-total-cache' ) . '</em>&hellip;
						</span>
					</p>
					<p class="hidden">
						' . esc_html__( 'Test URL:', 'w3-total-cache' ) . ' <span id="w3tc-test-url"></span>
					</p>
					<table id="w3tc-pgcache-table" class="w3tc-setupguide-table widefat striped hidden">
						<thead>
							<tr>
								<th>' . esc_html__( 'Select', 'w3-total-cache' ) . '</th>
								<th>' . esc_html__( 'Storage Engine', 'w3-total-cache' ) . '</th>
								<th>' . esc_html__( 'Time (ms)', 'w3-total-cache' ) . '</th>
							</tr>
						</thead>
						<tbody></tbody>
					</table>',
				),
				array( // Database Cache.
					'headline' => __( 'Database Cache', 'w3-total-cache' ),
					'id'       => 'dbc1',
					'markup'   => '<p>' .
						esc_html__(
							'Many database queries are made in every dynamic page request.  A database cache may speed up the generation of dynamic pages.  Database Cache serves query results directly from a storage engine.',
							'w3-total-cache'
						) . '</p>
						<p>
						<input id="w3tc-test-dbcache" class="button-primary" type="button" value="' .
						esc_html__( 'Test Database Cache', 'w3-total-cache' ) . '">
						<span class="hidden"><span class="spinner inline"></span>' . esc_html__( 'Testing', 'w3-total-cache' ) .
						' <em>' . esc_html__( 'Database Cache', 'w3-total-cache' ) . '</em>&hellip;
						</span>
						</p>
						<table id="w3tc-dbc-table" class="w3tc-setupguide-table widefat striped hidden">
							<thead>
								<tr>
									<th>' . esc_html__( 'Select', 'w3-total-cache' ) . '</th>
									<th>' . esc_html__( 'Storage Engine', 'w3-total-cache' ) . '</th>
									<th>' . esc_html__( 'Time (ms)', 'w3-total-cache' ) . '</th>
								</tr>
							</thead>
							<tbody></tbody>
						</table>
						<div id="w3tc-dbcache-recommended" class="notice notice-info inline hidden">
						<div class="w3tc-notice-recommended"><span class="dashicons dashicons-lightbulb"></span> Recommended</div>
						<div><p>' .
						esc_html__(
							'By default, this feature is disabled.  We recommend using Redis or Memcached, otherwise leave this feature disabled as the server database engine may be faster than using disk caching.',
							'w3-total-cache'
						) . '</p></div>
						</div>',
				),
				array( // Object Cache.
					'headline' => __( 'Object Cache', 'w3-total-cache' ),
					'id'       => 'oc1',
					'markup'   => '<p>' .
						esc_html__(
							'WordPress caches objects used to build pages, but does not reuse them for future page requests.',
							'w3-total-cache'
						) . '</p>
						<p><strong>' . esc_html__( 'W3 Total Cache', 'w3-total-cache' ) . '</strong> ' .
						esc_html__( 'can help you speed up dynamic pages by persistently storing objects.', 'w3-total-cache' ) .
						'</p>
						<p>
						<input id="w3tc-test-objcache" class="button-primary" type="button" value="' .
						esc_html__( 'Test Object Cache', 'w3-total-cache' ) . '">
						<span class="hidden"><span class="spinner inline"></span>' . esc_html__( 'Testing', 'w3-total-cache' ) .
						' <em>' . esc_html__( 'Object Cache', 'w3-total-cache' ) . '</em>&hellip;
						</span>
						</p>
						<table id="w3tc-objcache-table" class="w3tc-setupguide-table widefat striped hidden">
							<thead>
								<tr>
									<th>' . esc_html__( 'Select', 'w3-total-cache' ) . '</th>
									<th>' . esc_html__( 'Storage Engine', 'w3-total-cache' ) . '</th>
									<th>' . esc_html__( 'Time (ms)', 'w3-total-cache' ) . '</th>
								</tr>
							</thead>
							<tbody></tbody>
						</table>',
				),
				array( // Browser Cache.
					'headline' => __( 'Browser Cache', 'w3-total-cache' ),
					'id'       => 'bc1',
					'markup'   => '<p>' .
						esc_html__(
							'To render your website, browsers must download many different types of assets, including javascript files, CSS stylesheets, images, and more.  For most assets, once a browser has downloaded them, they shouldn\'t have to download them again.',
							'w3-total-cache'
						) . '</p>
						<p><strong>' . esc_html__( 'W3 Total Cache', 'w3-total-cache' ) . '</strong> ' .
						esc_html__(
							'can help ensure browsers are properly caching your assets.',
							'w3-total-cache'
						) . '</p>
						<p>' . sprintf(
							// translators: 1: HTML emphesis open tag, 2: HTML emphesis close tag.
							esc_html__(
								'The %1$sCache-Control%2$s header tells your browser how it should cache specific files.  The %1$smax-age%2$s setting tells your browser how long, in seconds, it should use its cached version of a file before requesting an updated one.',
								'w3-total-cache'
							),
							'<em>',
							'</em>'
						) . '</p>
						<p>' . sprintf(
							// translators: 1: HTML emphesis open tag, 2: HTML emphesis close tag.
							esc_html__(
								'To improve %1$sBrowser Cache%2$s, we recommend enabling %1$sBrowser Cache%2$s.',
								'w3-total-cache'
							),
							'<em>',
							'</em>'
						) . '</p>
						<input id="w3tc-test-browsercache" class="button-primary" type="button" value="' .
						esc_html__( 'Test Browser Cache', 'w3-total-cache' ) . '">
						<span class="hidden"><span class="spinner inline"></span>' . esc_html__( 'Testing', 'w3-total-cache' ) .
						' <em>' . esc_html__( 'Browser Cache', 'w3-total-cache' ) . '</em>&hellip;
						</span>
						</p>
						<table id="w3tc-browsercache-table" class="w3tc-setupguide-table widefat striped hidden">
						<thead>
						<tr>
							<th>' . esc_html__( 'Setting', 'w3-total-cache' ) . '</th>
							<th>' . esc_html__( 'File', 'w3-total-cache' ) . '</th>
							<th>' . esc_html__( 'Cache-Control Header', 'w3-total-cache' ) . '</th>
						</tr>
						</thead>
						<tbody></tbody>
						</table>',
				),
				array( // Lazy load.
					'headline' => __( 'Lazy Load', 'w3-total-cache' ),
					'id'       => 'll1',
					'markup'   => '<p>' .
						esc_html__(
							'Pages containing images and other objects can have their load time reduced by deferring them until they are needed.  For example, images can be loaded when a visitor scrolls down the page to make them visible.',
							'w3-total-cache'
						) . '</p>
						<p>
						<input type="checkbox" id="lazyload-enable" value="1" /> <label for="lazyload-enable">' .
						esc_html__( 'Lazy Load Images', 'w3-total-cache' ) . '</label></p>',
				),
				array( // Setup complete.
					'headline' => __( 'Setup Complete!', 'w3-total-cache' ),
					'id'       => 'complete',
					'markup'   => '<p>' .
						sprintf(
							// translators: 1: HTML strong open tag, 2: HTML strong close tag, 3: Label.
							esc_html__(
								'%1$sPage Cache%2$s engine set to %1$s%3$s%2$s',
								'w3-total-cache'
							),
							'<strong>',
							'</strong>',
							'<span id="w3tc-pgcache-engine">' . esc_html__( 'UNKNOWN', 'w3-total-cache' ) . '</span>'
						) . '</p>
						<p>' .
						sprintf(
							// translators: 1: HTML strong open tag, 2: HTML strong close tag.
							esc_html__(
								'%1$sTime to First Byte%2$s has changed by %1$s%3$s%2$s',
								'w3-total-cache'
							),
							'<strong>',
							'</strong>',
							'<span id="w3tc-ttfb-diff">0%</span>'
						) . '</p>
						<p>' .
						sprintf(
							// translators: 1: HTML strong open tag, 2: HTML strong close tag, 3: Label.
							esc_html__(
								'%1$sDatabase Cache%2$s engine set to %1$s%3$s%2$s',
								'w3-total-cache'
							),
							'<strong>',
							'</strong>',
							'<span id="w3tc-dbcache-engine">' . esc_html__( 'UNKNOWN', 'w3-total-cache' ) . '</span>'
						) . '</p>
						<p>' .
						sprintf(
							// translators: 1: HTML strong open tag, 2: HTML strong close tag, 3: Label.
							esc_html__(
								'%1$sObject Cache%2$s engine set to %1$s%3$s%2$s',
								'w3-total-cache'
							),
							'<strong>',
							'</strong>',
							'<span id="w3tc-objcache-engine">' . esc_html__( 'UNKNOWN', 'w3-total-cache' ) . '</span>'
						) . '</p>
						<p>' .
						sprintf(
							// translators: 1: HTML strong open tag, 2: HTML strong close tag, 3: Label.
							esc_html__(
								'%1$sBrowser Cache%2$s headers set for JavaScript, CSS, and images? %1$s%3$s%2$s',
								'w3-total-cache'
							),
							'<strong>',
							'</strong>',
							'<span id="w3tc-browsercache-setting">' . esc_html__( 'UNKNOWN', 'w3-total-cache' ) . '</span>'
						) . '</p>
						<p>' . sprintf(
							// translators: 1: HTML strong open tag, 2: HTML strong close tag, 3: Label.
							esc_html__(
								'%1$sLazy Load%2$s images? %1$s%3$s%2$s',
								'w3-total-cache'
							),
							'<strong>',
							'</strong>',
							'<span id="w3tc-lazyload-setting">' . esc_html__( 'UNKNOWN', 'w3-total-cache' ) . '</span>'
						) . '</p>
						<h3>' . esc_html__( 'What\'s Next?', 'w3-total-cache' ) . '</h3>
						<p>' .
						sprintf(
							// translators: 1: HTML emphesis open tag, 2: HTML emphesis close tag.
							esc_html__(
								'Your website\'s performance can still be improved by configuring %1$sminify%2$s settings, setting up a %1$sCDN%2$s, and more!',
								'w3-total-cache'
							),
							'<strong>',
							'</strong>'
						) . '</p>
						<p>' .
						sprintf(
							// translators: 1: Anchor/link open tag, 2: Anchor/link close tag.
							esc_html__(
								'Please visit %1$sGeneral Settings%2$s to learn more about these features.',
								'w3-total-cache'
							),
							'<a href="' . esc_url(
								$force_master_config || is_network_admin() ?
								network_admin_url( 'admin.php?page=w3tc_general' ) : admin_url( 'admin.php?page=w3tc_general' )
							) . '">',
							'</a>'
						) . '</p>
						<h3>' . esc_html__( 'Need help?', 'w3-total-cache' ) . '</h3>
						<p>' .
						sprintf(
							// translators: 1: Anchor/link open tag, 2: Anchor/link close tag.
							esc_html__(
								'We\'re here to help you!  Visit our %1$sSupport Center%2$s for helpful information and to ask questions.',
								'w3-total-cache'
							),
							'<a href="' . esc_url( 'https://www.boldgrid.com/support/w3-total-cache/' ) . '" target="_blank">',
							'</a>'
						) . '</p>',
				),
			),
		);
	}
}
