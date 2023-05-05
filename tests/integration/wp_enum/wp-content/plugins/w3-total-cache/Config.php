<?php
namespace W3TC;

/**
 * class Config
 * Provides configuration data using cache
 */
class Config {
	/*
	 * blog id of loaded config
	 * @var integer
	 */
	private $_blog_id;
	private $_is_master;

	/*
	 * Is this preview config
	 * @var boolean
	 */
	private $_preview;

	private $_md5;
	private $_data;
	private $_compiled;



	/**
	 * Reads config from file and returns it's content as array (or null)
	 * Stored in this class to limit class loading
	 */
	static public function util_array_from_storage( $blog_id, $preview ) {
		if ( !defined( 'W3TC_CONFIG_CACHE_ENGINE' ) ) {
			return self::_util_array_from_storage( $blog_id, $preview );
		}

		// config cache enabled
		$config = ConfigCache::util_array_from_storage( $blog_id, $preview );
		if ( !is_null( $config ) ) {
			return $config;
		}

		$config = self::_util_array_from_storage( $blog_id, $preview );
		ConfigCache::save_item( $blog_id, $preview, $config );
		return $config;
	}



	static private function _util_array_from_storage( $blog_id, $preview ) {
		if ( defined( 'W3TC_CONFIG_DATABASE' ) && W3TC_CONFIG_DATABASE ) {
			return ConfigDbStorage::util_array_from_storage( $blog_id, $preview );
		}

		$filename = self::util_config_filename( $blog_id, $preview );
		if ( file_exists( $filename ) && is_readable( $filename ) ) {
			// including file directly instead of read+eval causes constant
			// problems with APC, ZendCache, and WSOD in a case of
			// broken config file
			$content = @file_get_contents( $filename );
			$config = @json_decode( substr( $content, 14 ), true );

			if ( is_array( $config ) ) {
				return $config;
			}
		}

		return null;
	}



	/*
	 * Returns config filename
	 * Stored in this class to limit class loading
	 */
	static public function util_config_filename( $blog_id, $preview ) {
		$postfix = ( $preview ? '-preview' : '' ) . '.php';

		if ( $blog_id <= 0 ) {
			$filename = W3TC_CONFIG_DIR . '/master' . $postfix;
		} else {
			$filename = W3TC_CONFIG_DIR . '/' . sprintf( '%06d', $blog_id ) . $postfix;
		}

		$d = w3tc_apply_filters( 'config_filename', array(
			'blog_id' => $blog_id,
			'preview' => $preview,
			'filename' => $filename
		) );

		return $d['filename'];
	}



	/*
	 * Returns config filename
	 * Stored in this class to limit class loading
	 * v = 0.9.5 - 0.9.5.1
	 */
	static public function util_config_filename_legacy_v2( $blog_id, $preview ) {
		$postfix = ( $preview ? '-preview' : '' ) . '.json';

		if ( $blog_id <= 0 )
			return W3TC_CONFIG_DIR . '/master' . $postfix;
		else
			return W3TC_CONFIG_DIR . '/' . sprintf( '%06d', $blog_id ) . $postfix;
	}



	public function __construct( $blog_id = null ) {
		if ( !is_null( $blog_id ) ) {
			$this->_blog_id = $blog_id;
			$this->_is_master = ( $this->_blog_id == 0 );
		} else {
			if ( Util_Environment::is_using_master_config() )
				$this->_blog_id = 0;
			else
				$this->_blog_id = Util_Environment::blog_id();

			$this->_is_master = ( Util_Environment::blog_id() == 0 );
		}

		$this->_preview = Util_Environment::is_preview_mode();
		$this->load();
	}



	/**
	 * Returns config value. Implementation for overriding
	 */
	public function get( $key, $default = null ) {
		$v = $this->_get( $this->_data, $key );
		if ( !is_null( $v ) )
			return $v;

		// take default value
		if ( !empty( $default ) || !function_exists( 'apply_filters' ) )
			return $default;

		// try cached default values
		static $default_values = null;
		if ( is_null( $default_values ) )
			$default_values = apply_filters( 'w3tc_config_default_values',
				array() );

		$v = $this->_get( $default_values, $key );
		if ( !is_null( $v ) )
			return $v;

		// update default values
		$default_values = apply_filters( 'w3tc_config_default_values',
			array() );

		$v = $this->_get( $default_values, $key );
		if ( !is_null( $v ) )
			return $v;

		return $default;
	}



	private function _get( &$a, $key ) {
		if ( is_array( $key ) ) {
			$key0 = $key[0];
			if ( isset( $a[$key0] ) ) {
				$key1 = $key[1];
				if ( isset( $a[$key0][$key1] ) )
					return $a[$key0][$key1];
			}
		} else if ( isset( $a[$key] ) ) {
				return $a[$key];
			}

		return null;
	}



	/**
	 * Returns string value
	 */
	public function get_string( $key, $default = '', $trim = true ) {
		$value = (string)$this->get( $key, $default );

		return $trim ? trim( $value ) : $value;
	}



	/**
	 * Returns integer value
	 */
	public function get_integer( $key, $default = 0 ) {
		return (integer)$this->get( $key, $default );
	}



	/**
	 * Returns boolean value
	 */
	public function get_boolean( $key, $default = false ) {
		return (boolean)$this->get( $key, $default );
	}



	/**
	 * Returns array value
	 */
	public function get_array( $key, $default = array() ) {
		return (array)$this->get( $key, $default );
	}



	/**
	 * Returns config value with ability to hook it.
	 * Should be called only when filters already loaded and
	 * call doesn't repeat too many times
	 */
	public function getf( $key, $default = null ) {
		$v = $this->get( $key, $default );
		return apply_filters( 'w3tc_config_item_' . $key, $v );
	}

	/**
	 * Returns string value with ability to hook it
	 */
	public function getf_string( $key, $default = '', $trim = true ) {
		$value = (string)$this->getf( $key, $default );

		return $trim ? trim( $value ) : $value;
	}

	/**
	 * Returns integer value with ability to hook it
	 */
	public function getf_integer( $key, $default = 0 ) {
		return (integer)$this->getf( $key, $default );
	}



	/**
	 * Returns boolean value ability to hook it
	 */
	public function getf_boolean( $key, $default = false ) {
		return (boolean)$this->getf( $key, $default );
	}



	/**
	 * Returns array value ability to hook it
	 */
	public function getf_array( $key, $default = array() ) {
		return (array)$this->getf( $key, $default );
	}



	/**
	 * Check if an extension is active
	 */
	public function is_extension_active( $extension ) {
		$extensions = $this->get_array( 'extensions.active' );
		return isset( $extensions[$extension] );
	}



	public function is_extension_active_frontend( $extension ) {
		$extensions = $this->get_array( 'extensions.active_frontend' );
		return isset( $extensions[$extension] );
	}



	public function set_extension_active_frontend( $extension,
		$is_active_frontend ) {
		$a = $this->get_array( 'extensions.active_frontend' );
		if ( !$is_active_frontend ) {
			unset( $a[$extension] );
		} else {
			$a[$extension] = '*';
		}

		$this->set( 'extensions.active_frontend', $a );
	}



	public function set_extension_active_dropin( $extension,
		$is_active_dropin ) {
		$a = $this->get_array( 'extensions.active_dropin' );
		if ( !$is_active_dropin ) {
			unset( $a[$extension] );
		} else {
			$a[$extension] = '*';
		}

		$this->set( 'extensions.active_dropin', $a );
	}



	/**
	 * Sets config value.
	 * Method to override
	 */
	public function set( $key, $value ) {
		if ( !is_array( $key ) ) {
			$this->_data[$key] = $value;
		} else {
			// set extension's key
			$key0 = $key[0];
			$key1 = $key[1];

			if ( !isset( $this->_data[$key0] ) || !is_array( $this->_data[$key0] ) )
				$this->_data[$key0] = array();

			$this->_data[$key0][$key1] = $value;
		}

		return $value;
	}



	/**
	 * Check if we are in preview mode
	 */
	public function is_preview() {
		return $this->_preview;
	}



	/**
	 * Returns true if we edit master config
	 */
	public function is_master() {
		return $this->_is_master;
	}



	public function is_compiled() {
		return $this->_compiled;
	}



	/**
	 * Sets default values
	 */
	public function set_defaults() {
		$c = new ConfigCompiler( $this->_blog_id, $this->_preview );
		$this->_data = $c->get_data();
	}



	/**
	 * Saves modified config
	 */
	public function save() {
		if ( function_exists( 'do_action' ) )
			do_action( 'w3tc_config_save', $this );

		$c = new ConfigCompiler( $this->_blog_id, $this->_preview );
		$c->apply_data( $this->_data );
		$c->save();
	}



	public function is_sealed( $key ) {
		if ( $this->is_master() )
			return false;

		// better to use master config data here, but
		// its faster and preciese enough for UI
		return ConfigCompiler::child_key_sealed( $key, $this->_data,
			$this->_data );
	}



	/**
	 * Exports config content
	 */
	public function export() {
		if ( defined( 'JSON_PRETTY_PRINT' ) )
			$content = json_encode( $this->_data, JSON_PRETTY_PRINT );
		else
			$content = json_encode( $this->_data );

		return $content;
	}



	/**
	 * Imports config content
	 */
	public function import( $filename ) {
		if ( file_exists( $filename ) && is_readable( $filename ) ) {
			$content = file_get_contents( $filename );
			if ( substr( $content, 0, 14 ) == '<?php exit; ?>' ) {
				$content = substr( $content, 14 );
			}

			$data = @json_decode( $content, true );
			if ( is_array( $data ) ) {
				if ( !isset( $data['version'] ) || $data['version'] != W3TC_VERSION ) {
					$c = new ConfigCompiler( $this->_blog_id, false );
					$c->load( $data );
					$data = $c->get_data();
				}

				foreach ( $data as $key => $value )
					$this->set( $key, $value );

				return true;
			}
		}

		return false;
	}



	public function get_md5() {
		if ( is_null( $this->_md5 ) )
			$this->_md5 = substr( md5( serialize( $this->_data ) ), 20 );
		return $this->_md5;
	}



	/**
	 * Loads config.
	 * In a case it finds out config files are of older version - uses slower
	 * loader which takes all possible bloglevel-overloads into account
	 * correctly
	 */
	public function load() {
		$data = Config::util_array_from_storage( 0, $this->_preview );

		// config file assumed is not up to date, use slow version
		if ( !isset( $data['version'] ) || $data['version'] != W3TC_VERSION )
			return $this->load_full();

		if ( !$this->is_master() ) {
			$child_data = Config::util_array_from_storage( $this->_blog_id,
				$this->_preview );

			if ( !is_null( $child_data ) ) {
				if ( !isset( $data['version'] ) || $data['version'] != W3TC_VERSION )
					return $this->load_full();

				foreach ( $child_data as $key => $value )
					$data[$key] = $value;
			}
		}

		$this->_data = $data;
		$this->_compiled = false;
	}



	/**
	 * Slower version of loader, used when configs belong to older w3tc version
	 */
	private function load_full() {
		$c = new ConfigCompiler( $this->_blog_id, $this->_preview );
		$c->load();
		$this->_data = $c->get_data();
		$this->_compiled = true;
	}
}
