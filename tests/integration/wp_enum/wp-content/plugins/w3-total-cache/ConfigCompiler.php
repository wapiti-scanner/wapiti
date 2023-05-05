<?php
namespace W3TC;

class ConfigCompiler {
	private $_blog_id;
	private $_preview;

	private $_data;
	private $_keys;



	/**
	 * Returns true is key is not modifiable anymore
	 * Placed here to limit class loading
	 *
	 * @return bool
	 */
	static public function child_key_sealed( $key, $master_data, $child_data ) {
		if ( isset( $master_data['common.force_master'] ) &&
			(boolean)$master_data['common.force_master'] )
			return true;

		// affects rules which are global, not possible to overload
		if ( $key == 'pgcache.engine' &&
			( $master_data['pgcache.engine'] == 'file_generic' ) )
			return true;
		if ( in_array( $key, array(
					'minify.rewrite',
					'browsercache.rewrite',
					'version' ) ) )
			return true;

		include W3TC_DIR . '/ConfigKeys.php';

		// key which marks overloads is always editable
		$overloads_postfix = '.configuration_overloaded';

		// extension settings sealing
		// e.g. array('newrelic' , '...') is controlled
		// by 'newrelic.configuration_overloaded']
		$block_key = ( is_array( $key ) ? $key[0] : $key );

		if ( isset( $child_data[$block_key] ) &&
			isset( $child_data[$block_key . $overloads_postfix] ) &&
			(boolean)$child_data[$block_key . $overloads_postfix] )
			return false;

		if ( !is_array( $key ) ) {
			if ( substr( $key, strlen( $key ) - strlen( $overloads_postfix ),
					strlen( $overloads_postfix ) ) == $overloads_postfix )
				return false;

			// default sealing
			foreach ( $overloading_keys_scope as $i ) {
				$overloading_key = $i['key'];

				// check if this key is allowed by overloading-mark key
				if ( substr( $key, 0, strlen( $i['prefix'] ) ) == $i['prefix'] ) {
					if ( !isset( $child_data[$overloading_key] ) )
						return true;
					if ( (boolean)$child_data[$overloading_key] )
						return false;
				}
			}
		}

		return true;
	}



	/**
	 * Reads config from file and returns it's content as array (or null)
	 * Stored in this class to limit class loading
	 */
	static private function util_array_from_file_legacy_v2( $filename ) {
		if ( file_exists( $filename ) && is_readable( $filename ) ) {
			// including file directly instead of read+eval causes constant
			// problems with APC, ZendCache, and WSOD in a case of
			// broken config file
			$content = @file_get_contents( $filename );
			$config = @json_decode( $content, true );

			if ( is_array( $config ) )
				return $config;
		}

		return null;
	}



	public function __construct( $blog_id, $preview ) {
		$this->_blog_id = $blog_id;
		$this->_preview = $preview;

		include W3TC_DIR . '/ConfigKeys.php';
		$this->_keys = $keys;

		// move _date to initial state
		foreach ( $this->_keys as $key => $value )
			$this->_data[$key] = $value['default'];

		$this->_data['version'] = W3TC_VERSION;

		$this->set_dynamic_defaults();
	}



	public function load( $data = null ) {
		// apply data from master config
		if ( is_null( $data ) ) {
			$data = Config::util_array_from_storage( 0, $this->_preview );
		}
		if ( is_null( $data ) && $this->_preview ) {
			// try to read production data when preview not available
			$data = Config::util_array_from_storage( 0, false );
		}

		// try to get legacy v2 data
		if ( is_null( $data ) ) {
			$master_filename = Config::util_config_filename_legacy_v2( 0,
				$this->_preview );
			$data = self::util_array_from_file_legacy_v2( $master_filename );
		}

		if ( is_array( $data ) ) {
			$data = $this->upgrade( $data );
			foreach ( $data as $key => $value )
				$this->_data[$key] = $value;
		}

		if ( $this->is_master() )
			return;


		// apply child config
		$data = Config::util_array_from_storage( $this->_blog_id,
			$this->_preview );
		if ( is_null( $data ) && $this->_preview ) {
			// try to read production data when preview not available
			$data = Config::util_array_from_storage( $this->_blog_id,
				false );
		}

		// try to get legacy v2 data
		if ( is_null( $data ) ) {
			$child_filename = Config::util_config_filename_legacy_v2(
				$this->_blog_id, $this->_preview );
			$data = self::util_array_from_file_legacy_v2( $child_filename );
		}

		if ( is_array( $data ) ) {
			$data = $this->upgrade( $data );
			foreach ( $data as $key => $value ) {
				if ( !ConfigCompiler::child_key_sealed( $key, $this->_data, $data ) )
					$this->_data[$key] = $value;
			}
		}
	}



	public function apply_data( $data ) {
		foreach ( $data as $key => $value )
			$this->_data[$key] = $value;
	}



	public function get_data() {
		return $this->_data;
	}



	public function save() {
		$data = array(
			'version' => $this->_data['version']
		);

		if ( $this->is_master() ) {
			foreach ( $this->_data as $key => $value )
				$data[$key] = $this->_data[$key];
		} else {
			// write only overwrited keys
			$master = new ConfigCompiler( 0, $this->_preview );
			$master->load();

			foreach ( $this->_data as $key => $value ) {
				if ( !ConfigCompiler::child_key_sealed( $key, $master->_data,
						$this->_data ) )
					$data[$key] = $this->_data[$key];
			}
		}

		ConfigUtil::save_item( $this->_blog_id, $this->_preview, $data );
	}


	/**
	 * Returns true if we edit master config
	 *
	 * @return boolean
	 */
	private function is_master() {
		return $this->_blog_id <= 0;
	}



	private function set_dynamic_defaults() {
		if ( empty( $this->_data['stats.access_log.webserver'] ) ) {
			if ( Util_Environment::is_nginx() ) {
				$this->_data['stats.access_log.webserver'] = 'nginx';
				$this->_data['stats.access_log.format'] = '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
			} else {
				$this->_data['stats.access_log.webserver'] = 'apache';
			}
		}

	}
	/**
	 * Apply new default values when version changes
	 */
	private function upgrade( $file_data ) {
		if ( !isset( $file_data['version'] ) ) {
			$file_data['version'] = '0.0.0';
		}

		if ( !function_exists( 'bb2_start' ) ) {
			$file_data['pgcache.bad_behavior_path'] = '';
		} else {
			if ( file_exists( WP_PLUGIN_DIR . '/bad-behavior/bad-behavior-generic.php' ) ) {
				$bb_file = WP_PLUGIN_DIR . '/bad-behavior/bad-behavior-generic.php';
			} elseif ( file_exists( WP_PLUGIN_DIR . '/Bad-Behavior/bad-behavior-generic.php' ) ) {
				$bb_file = WP_PLUGIN_DIR . '/Bad-Behavior/bad-behavior-generic.php';
			} else {
				$bb_file = false;
			}

			if ( $bb_file ) {
				$file_data['pgcache.bad_behavior_path'] = $bb_file;
			}
		}

		//
		// changes in 0.15.2
		//
		if ( version_compare( $file_data['version'], '0.15.2', '<' ) ) {
			if ( isset( $file_data['minify.js.combine.header'] ) && $file_data['minify.js.combine.header'] ) {
				$file_data['minify.js.method'] = 'combine';
			}

			if ( isset( $file_data['minify.css.combine'] ) && $file_data['minify.css.combine'] ) {
				$file_data['minify.css.method'] = 'combine';
			}
		}

		//
		// changes in 0.13
		//
		if ( version_compare( $file_data['version'], '0.12.0', '<=' ) ) {
			if ( empty( $file_data['lazyload.exclude'] ) ) {
				$file_data['lazyload.exclude'] = array();
			}

			if ( !in_array( 'skip_lazy', $file_data['lazyload.exclude'] ) ) {
				$file_data['lazyload.exclude'][] = 'skip_lazy';
			}
		}

		//
		// changes in 0.9.7
		//
		if ( isset( $file_data['cdnfsd.enabled'] ) &&
			$file_data['cdnfsd.enabled'] == '1' &&
			empty( $file_data['cdnfsd.engine'] ) ) {
			$file_data['cdnfsd.enabled'] = '0';
		}

		//
		// changes in 0.9.6
		//
		if ( !isset( $file_data['cdn.cors_header'] ) ) {
			$file_data['cdn.cors_header'] = true;
		}

		//
		// changes in 0.9.5
		//
		if ( !isset( $file_data['extensions.active_frontend'] ) ||
			!is_array( $file_data['extensions.active_frontend'] ) )
			$file_data['extensions.active_frontend'] = array();

		if ( version_compare( $file_data['version'], '0.9.5', '<' ) ) {
			// dont show minify tips if already enabled
			if ( isset( $file_data['minify.enabled'] ) &&
				$file_data['minify.enabled'] == 'true' &&
				function_exists( 'get_option' ) ) {
				$cs = Dispatcher::config_state();
				$cs->set( 'minify.hide_minify_help', true );
				$cs->save();
			}
			$file_data['pgcache.mirrors.enabled'] = true;

			// map regions in rackspace
			if ( isset( $file_data['cdn.rscf.location'] ) ) {
				if ( $file_data['cdn.rscf.location'] == 'uk' )
					$file_data['cdn.rscf.location'] = 'LON';
				if ( $file_data['cdn.rscf.location'] == 'us' )
					$file_data['cdn.rscf.location'] = 'ORD';
			}

			// change filenames
			$active = array();

			if ( isset( $file_data['extensions.active'] ) &&
				is_array( $file_data['extensions.active'] ) ) {
				if ( isset( $file_data['extensions.active']['cloudflare'] ) )
					$active['cloudflare'] = 'w3-total-cache/Extension_CloudFlare_Plugin.php';
				if ( isset( $file_data['extensions.active']['genesis.theme'] ) )
					$active['genesis.theme'] = 'w3-total-cache/Extension_Genesis_Plugin.php';
				if ( isset( $file_data['extensions.active']['wordpress-seo'] ) )
					$active['wordpress-seo'] = 'w3-total-cache/Extension_WordPressSeo_Plugin.php';
			}
			$file_data['extensions.active'] = $active;

			$active_frontend = array();
			foreach ( $active as $key => $value )
				$active_frontend[$key] = '*';

			$file_data['extensions.active_frontend'] = $active_frontend;

			// keep those active by default
			$file_data['extensions.active']['newrelic'] =
				'w3-total-cache/Extension_NewRelic_Plugin.php';
			$file_data['extensions.active']['fragmentcache'] =
				'w3-total-cache/Extension_FragmentCache_Plugin.php';
		}

		// newrelic settings - migrate to extension
		if ( isset( $file_data['newrelic.enabled'] ) &&
			$file_data['newrelic.enabled'] ) {
			// make new relic extension enabled
			if ( !isset( $file_data['extensions.active_frontend']['newrelic'] ) )
				$file_data['extensions.active_frontend']['newrelic'] ='*';
		}

		if ( !isset( $file_data['newrelic'] ) ||
			!is_array( $file_data['newrelic'] ) )
			$file_data['newrelic'] = array(
				'monitoring_type' => 'apm'
			);

		$this->_set_if_exists( $file_data, 'newrelic.api_key',
			'newrelic', 'api_key' );
		$this->_set_if_exists( $file_data, 'newrelic.appname',
			'newrelic', 'apm.application_name' );
		$this->_set_if_exists( $file_data, 'newrelic.accept.logged_roles',
			'newrelic', 'accept.logged_roles' );
		$this->_set_if_exists( $file_data, 'newrelic.accept.roles',
			'newrelic', 'accept.roles' );
		$this->_set_if_exists( $file_data, 'newrelic.use_php_function',
			'newrelic', 'use_php_function' );
		$this->_set_if_exists( $file_data, 'newrelic.cache_time',
			'newrelic', 'cache_time' );
		$this->_set_if_exists( $file_data, 'newrelic.enable_xmit',
			'newrelic', 'enable_xmit' );
		$this->_set_if_exists( $file_data, 'newrelic.include_rum',
			'newrelic', 'include_rum' );

		// extensions - kept in separate key now
		$this->_set_if_exists_extension( $file_data, 'cloudflare' );
		$this->_set_if_exists_extension( $file_data, 'genesis.theme' );

		// fragmentcache to extension
		if ( isset( $file_data['fragmentcache.enabled'] ) &&
			$file_data['fragmentcache.enabled'] ) {
			// make new relic extension enabled
			if ( !isset( $file_data['extensions.active_frontend']['fragmentcache'] ) )
				$file_data['extensions.active_frontend']['fragmentcache'] = '*';
		}

		$this->_set_if_exists( $file_data, 'fragmentcache.debug',
			'fragmentcache', 'debug' );
		$this->_set_if_exists( $file_data, 'fragmentcache.engine',
			'fragmentcache', 'engine' );
		$this->_set_if_exists( $file_data, 'fragmentcache.file.gc',
			'fragmentcache', 'file.gc' );
		$this->_set_if_exists( $file_data, 'fragmentcache.file.locking',
			'fragmentcache', 'file.locking' );
		$this->_set_if_exists( $file_data, 'fragmentcache.memcached.servers',
			'fragmentcache', 'memcached.servers' );
		$this->_set_if_exists( $file_data, 'fragmentcache.memcached.persistent',
			'fragmentcache', 'memcached.persistent' );
		$this->_set_if_exists( $file_data, 'fragmentcache.memcached.aws_autodiscovery',
			'fragmentcache', 'memcached.aws_autodiscovery' );
		$this->_set_if_exists( $file_data, 'fragmentcache.memcached.username',
			'fragmentcache', 'memcached.username' );
		$this->_set_if_exists( $file_data, 'fragmentcache.memcached.password',
			'fragmentcache', 'memcached.password' );
		$this->_set_if_exists( $file_data, 'fragmentcache.memcached.binary_protocol',
			'fragmentcache', 'memcached.binary_protocol' );
		$this->_set_if_exists( $file_data, 'fragmentcache.redis.persistent',
			'fragmentcache', 'redis.persistent' );
		$this->_set_if_exists( $file_data, 'fragmentcache.redis.servers',
			'fragmentcache', 'redis.servers' );
		$this->_set_if_exists( $file_data, 'fragmentcache.redis.verify_tls_certificates',
			'fragmentcache', 'redis.verify_tls_certificates' );
		$this->_set_if_exists( $file_data, 'fragmentcache.redis.password',
			'fragmentcache', 'redis.password' );
		$this->_set_if_exists( $file_data, 'fragmentcache.redis.dbid',
			'fragmentcache', 'redis.dbid' );
		$this->_set_if_exists( $file_data, 'fragmentcache.lifetime',
			'fragmentcache', 'lifetime' );


		// new options, separated old one. implemented in 0.9.5.3
		if ( isset( $file_data['browsercache.cssjs.replace'] ) &&
			!isset( $file_data['browsercache.cssjs.querystring'] ) ) {
			$file_data['browsercache.cssjs.querystring'] = $file_data['browsercache.cssjs.replace'];
		}
		if ( isset( $file_data['browsercache.other.replace'] ) &&
			!isset( $file_data['browsercache.other.querystring'] ) ) {
			$file_data['browsercache.other.querystring'] = $file_data['browsercache.other.replace'];
		}

		//
		// changes in 0.9.5.4
		//
		if ( isset( $file_data['cdn.engine'] ) ) {
			if ( $file_data['cdn.engine'] == 'cloudfront_fsd' ) {
				$file_data['cdnfsd.engine'] = 'cloudfront';
				$file_data['cdnfsd.enabled'] = $file_data['cdn.enabled'];

				if ( isset( $file_data['cdn.cloudfront_fsd.access_key'] ) ) {
					$file_data['cdnfsd.cloudfront.access_key'] =
						$file_data['cdn.cloudfront_fsd.access_key'];
					$file_data['cdnfsd.cloudfront.distribution_domain'] =
						$file_data['cdn.cloudfront_fsd.distribution_domain'];
					$file_data['cdnfsd.cloudfront.secret_key'] =
						$file_data['cdn.cloudfront_fsd.secret_key'];
					$file_data['cdnfsd.cloudfront.distribution_id'] =
						$file_data['cdn.cloudfront_fsd.distribution_id'];
				}
			}
		}

		$file_data['version'] = W3TC_VERSION;

		return $file_data;
	}



	private function _set_if_exists_extension( &$a, $extension ) {
		if ( isset( $a['extensions.settings'] ) &&
			isset( $a['extensions.settings'][$extension] ) ) {
			$a[$extension] = $a['extensions.settings'][$extension];
			unset( $a['extensions.settings'][$extension] );
		}
	}



	private function _set_if_exists( &$a, $old_key, $new_key0, $new_key1 ) {
		if ( isset( $a[$old_key] ) ) {
			$a[$new_key0][$new_key1] = $a[$old_key];
			unset( $a[$old_key] );
		}
	}
}
