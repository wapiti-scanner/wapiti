<?php
namespace W3TC;

/**
 * Interplugin communication
 */
class Dispatcher {
	static private $instances = array();

	/**
	 * return component instance
	 */
	static public function component( $class ) {
		if ( !isset( self::$instances[$class] ) ) {
			$full_class = '\\W3TC\\' . $class;
			self::$instances[$class] = new $full_class();
		}

		$v = self::$instances[$class];   // Don't return reference
		return $v;
	}



	static public function config() {
		return self::component( 'Config' );
	}



	static public function reset_config() {
		unset(self::$instances['Config']);
	}



	static public function config_master() {
		static $config_master = null;

		if ( is_null( $config_master ) ) {
			$config_master = new Config( 0 );
		}

		return $config_master;
	}



	static public function config_state() {
		if ( Util_Environment::blog_id() <= 0 )
			return self::config_state_master();

		static $config_state = null;

		if ( is_null( $config_state ) )
			$config_state = new ConfigState( false );

		return $config_state;
	}



	static public function config_state_master() {
		static $config_state = null;

		if ( is_null( $config_state ) )
			$config_state = new ConfigState( true );

		return $config_state;
	}



	static public function config_state_note() {
		static $o = null;

		if ( is_null( $o ) )
			$o = new ConfigStateNote( self::config_state_master(),
				self::config_state() );

		return $o;
	}



	/**
	 * Checks if specific local url is uploaded to CDN
	 *
	 * @param string  $url
	 * @return bool
	 */
	static public function is_url_cdn_uploaded( $url ) {
		$minify_enabled = self::config()->get_boolean( 'minify.enabled' );
		if ( $minify_enabled ) {
			$minify = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );
			$data = $minify->get_url_custom_data( $url );
			if ( is_array( $data ) && isset( $data['cdn.status'] ) && $data['cdn.status'] == 'uploaded' ) {
				return true;
			}
		}
		// supported only for minify-based urls, futher is not needed now
		return false;
	}



	/**
	 * Creates file for CDN upload.
	 * Needed because minify can handle urls of non-existing files but CDN needs
	 * real file to upload it
	 */
	static public function create_file_for_cdn( $filename ) {
		$minify_enabled = self::config()->get_boolean( 'minify.enabled' );
		if ( $minify_enabled ) {
			$minify_document_root = Util_Environment::cache_blog_dir( 'minify' ) . '/';

			if ( !substr( $filename, 0, strlen( $minify_document_root ) ) == $minify_document_root ) {
				// unexpected file name
				return;
			}

			$short_filename = substr( $filename, strlen( $minify_document_root ) );
			$minify = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );

			$data = $minify->process( $short_filename, true );

			if ( !file_exists( $filename ) && isset( $data['content'] ) ) {

				if ( !file_exists( dirname( $filename ) ) )
					Util_File::mkdir_from_safe( dirname( $filename ), W3TC_CACHE_DIR );
			}
			@file_put_contents( $filename, $data['content'] );
		}
	}



	/**
	 * Called on successful file upload to CDN
	 *
	 * @param unknown $file_name
	 */
	static public function on_cdn_file_upload( $file_name ) {
		$minify_enabled = self::config()->get_boolean( 'minify.enabled' );
		if ( $minify_enabled ) {
			$minify_document_root = Util_Environment::cache_blog_dir( 'minify' ) . '/';

			if ( !substr( $file_name, 0, strlen( $minify_document_root ) ) == $minify_document_root ) {
				// unexpected file name
				return;
			}

			$short_file_name = substr( $file_name, strlen( $minify_document_root ) );
			$minify = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );
			$minify->set_file_custom_data( $short_file_name,
				array( 'cdn.status' => 'uploaded' ) );
		}
	}



	/**
	 * Returns common rules used by nginx for files belonging to browsercache
	 * section
	 * TODO: change to filters, like litespeed does
	 */
	static public function nginx_rules_for_browsercache_section( $config, $section,
			$extra_add_headers_set = false ) {
		$rules = array(
			'other' => array(),
			'add_header' => array()
		);
		if ( $config->get_boolean( 'browsercache.enabled' ) ) {
			$o = new BrowserCache_Environment_Nginx( $config );
			$rules = $o->section_rules( $section, $extra_add_headers_set );
		}

		if ( !empty( $rules['add_header'] ) &&
				$config->get_boolean( 'cdn.enabled' ) ) {
			$o = new Cdn_Environment_Nginx( $config );
			$rule = $o->generate_canonical();

			if ( !empty( $rule ) ) {
				$rules['add_header'][] = $rule;
			}
		}

		return array_merge( $rules['other'], $rules['add_header'] );
	}



	/**
	 * Called when minify going to process request of some minified file
	 */
	static public function requested_minify_filename( $config, $file ) {
		// browsercache may alter filestructure, allow it to remove its
		// uniqualizator
		if ( $config->get_boolean( 'browsercache.enabled' ) &&
			$config->get_boolean( 'browsercache.rewrite' ) ) {
			if ( preg_match( '~(.+)\.([0-9a-z]+)(\.[^.]+)$~', $file, $m ) )
				$file = $m[1] . $m[3];
		}
		return $file;
	}



	/**
	 * Usage statistics uses one of other module's cache
	 * to store its temporary data
	 */
	static public function get_usage_statistics_cache() {
		static $cache = null;
		if ( is_null( $cache ) ) {
			$c = Dispatcher::config();
			$engineConfig = null;
			if ( $c->get_boolean( 'objectcache.enabled' ) ) {
				$provider = Dispatcher::component( 'ObjectCache_WpObjectCache_Regular' );
			} else if ( $c->get_boolean( 'dbcache.enabled' ) ) {
				$provider = Dispatcher::component( 'DbCache_Core' );
			} else if ( $c->get_boolean( 'pgcache.enabled' ) ) {
				$provider = Dispatcher::component( 'PgCache_ContentGrabber' );
			} else if ( $c->get_boolean( 'minify.enabled' ) ) {
				$provider = Dispatcher::component( 'Minify_Core' );
			} else {
				$engineConfig = array( 'engine' => 'file' );
			}

			if ( is_null( $engineConfig ) ) {
				$engineConfig = $provider->get_usage_statistics_cache_config();
			}

			$engineConfig['module'] = 'stats';
			$engineConfig['blog_id'] = 0;   // count wpmu-wide stats

			if ( $engineConfig['engine'] == 'file' ) {
				$engineConfig['cache_dir'] = Util_Environment::cache_dir( 'stats' );
			}

			$cache = Cache::instance( $engineConfig['engine'],
				$engineConfig );
		}

		return $cache;
	}



	/**
	 * In a case request processing has been finished before WP initialized,
	 * but usage statistics metrics should be counted.
	 * To work properly $metrics_function has to be added also by plugin
	 * when add_action is available.
	 */
	static public function usage_statistics_apply_before_init_and_exit(
		$metrics_function ) {
		$c = Dispatcher::config();
		if ( !$c->get_boolean( 'stats.enabled' ) ) {
			exit();
		}

		$core = Dispatcher::component( 'UsageStatistics_Core' );
		$core->apply_metrics_before_init_and_exit( $metrics_function );
	}
}
