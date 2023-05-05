<?php
namespace W3TC;

class Util_Rule {
	/**
	 * Check if WP permalink directives exists
	 *
	 * @return boolean
	 */
	static public function is_permalink_rules() {
		if ( ( Util_Environment::is_apache() || Util_Environment::is_litespeed() ) && !Util_Environment::is_wpmu() ) {
			$path = Util_Rule::get_pgcache_rules_core_path();

			return ( $data = @file_get_contents( $path ) ) &&
				strstr( $data, W3TC_MARKER_BEGIN_WORDPRESS ) !== false;
		}

		return true;
	}

	/**
	 * Removes empty elements
	 */
	static public function array_trim( &$a ) {
		for ( $n = count( $a ) - 1; $n >= 0; $n-- ) {
			if ( empty( $a[$n] ) )
				array_splice( $a, $n, 1 );
		}
	}

	/**
	 * Returns nginx rules path
	 *
	 * @return string
	 */
	static public function get_nginx_rules_path() {
		$config = Dispatcher::config();

		$path = $config->get_string( 'config.path' );

		if ( !$path ) {
			$path = Util_Environment::site_path() . 'nginx.conf';
		}

		return $path;
	}

	/**
	 * Returns litespeed rules path
	 *
	 * @return string
	 */
	static public function get_litespeed_rules_path() {
		$config = Dispatcher::config();

		$path = $config->get_string( 'config.path' );

		if ( !$path ) {
			$path = Util_Environment::site_path() . 'litespeed.conf';
		}

		return $path;
	}

	/**
	 * Returns path of apache's primary rules file
	 *
	 * @return string
	 */
	static public function get_apache_rules_path() {
		return Util_Environment::site_path() . '.htaccess';
	}

	/**
	 * Returns path of pagecache core rules file
	 *
	 * @return string
	 */
	static public function get_pgcache_rules_core_path() {
		switch ( true ) {
		case Util_Environment::is_apache():
		case Util_Environment::is_litespeed():
			return Util_Rule::get_apache_rules_path();

		case Util_Environment::is_nginx():
			return Util_Rule::get_nginx_rules_path();
		}

		return false;
	}

	/**
	 * Returns path of browsercache cache rules file
	 *
	 * @return string
	 */
	static public function get_browsercache_rules_cache_path() {
		if ( Util_Environment::is_litespeed() ) {
			return Util_Rule::get_litespeed_rules_path();
		}

		return Util_Rule::get_pgcache_rules_core_path();
	}

	/**
	 * Returns path of minify rules file
	 *
	 * @return string
	 */
	static public function get_minify_rules_core_path() {
		switch ( true ) {
		case Util_Environment::is_apache():
		case Util_Environment::is_litespeed():
			return W3TC_CACHE_MINIFY_DIR . DIRECTORY_SEPARATOR . '.htaccess';

		case Util_Environment::is_nginx():
			return Util_Rule::get_nginx_rules_path();
		}

		return false;
	}

	/**
	 * Returns path of minify rules file
	 *
	 * @return string
	 */
	static public function get_minify_rules_cache_path() {
		switch ( true ) {
		case Util_Environment::is_apache():
		case Util_Environment::is_litespeed():
			return W3TC_CACHE_MINIFY_DIR . DIRECTORY_SEPARATOR . '.htaccess';

		case Util_Environment::is_nginx():
			return Util_Rule::get_nginx_rules_path();
		}

		return false;
	}

	/**
	 * Returns path of CDN rules file
	 *
	 * @return string
	 */
	static public function get_cdn_rules_path() {
		switch ( true ) {
		case Util_Environment::is_apache():
		case Util_Environment::is_litespeed():
			return '.htaccess';

		case Util_Environment::is_nginx():
			return 'nginx.conf';
		}

		return false;
	}

	static public function get_new_relic_rules_core_path() {
		return Util_Rule::get_pgcache_rules_core_path();
	}

	/**
	 * Returns true if we can modify rules
	 *
	 * @param string  $path
	 * @return boolean
	 */
	static public function can_modify_rules( $path ) {
		if ( Util_Environment::is_wpmu() ) {
			if ( Util_Environment::is_apache() || Util_Environment::is_litespeed() || Util_Environment::is_nginx() ) {
				switch ( $path ) {
				case Util_Rule::get_pgcache_rules_cache_path():
				case Util_Rule::get_minify_rules_core_path():
				case Util_Rule::get_minify_rules_cache_path():
					return true;
				}
			}

			return false;
		}

		return true;
	}

	/**
	 * Trim rules
	 *
	 * @param string  $rules
	 * @return string
	 */
	static public function trim_rules( $rules ) {
		$rules = trim( $rules );

		if ( $rules != '' ) {
			$rules .= "\n";
		}

		return $rules;
	}

	/**
	 * Cleanup rewrite rules
	 *
	 * @param string  $rules
	 * @return string
	 */
	static public function clean_rules( $rules ) {
		$rules = preg_replace( '~[\r\n]+~', "\n", $rules );
		$rules = preg_replace( '~^\s+~m', '', $rules );
		$rules = Util_Rule::trim_rules( $rules );

		return $rules;
	}

	/**
	 * Erases text from start to end
	 *
	 * @param string  $rules
	 * @param string  $start
	 * @param string  $end
	 * @return string
	 */
	static public function erase_rules( $rules, $start, $end ) {
		$r = '~' . Util_Environment::preg_quote( $start ) . "\n.*?" . Util_Environment::preg_quote( $end ) . "\n*~s";

		$rules = preg_replace( $r, '', $rules );
		$rules = Util_Rule::trim_rules( $rules );

		return $rules;
	}

	/**
	 * Check if rules exist
	 *
	 * @param string  $rules
	 * @param string  $start
	 * @param string  $end
	 * @return int
	 */
	static public function has_rules( $rules, $start, $end ) {
		return preg_match( '~' . Util_Environment::preg_quote( $start ) . "\n.*?" . Util_Environment::preg_quote( $end ) . "\n*~s", $rules );
	}

	/**
	 *
	 *
	 * @param Util_Environment_Exceptions $exs exceptions to fill on error
	 * @param string  $path filename of rules file to modify
	 * @param string  $rules rules to add
	 * @param string  $start start marker
	 * @param string  $end end marker
	 * @param array   $order order where to place if some marker exists
	 * @param boolean $remove_wpsc if WPSC rules should be removed to avoid
	 *                  inconsistent rules generation
	 */
	static public function add_rules( $exs, $path, $rules, $start, $end, $order,
			$remove_wpsc = false ) {
		if ( empty( $path ) ) {
			return;
		}

		$data = @file_get_contents( $path );
		if ( empty( $data ) ) {
			$data = '';
		}

		$modified = false;
		if ( $remove_wpsc ) {
			if ( Util_Rule::has_rules(
					$data,
					W3TC_MARKER_BEGIN_PGCACHE_WPSC,
					W3TC_MARKER_END_PGCACHE_WPSC ) ) {
				$data = Util_Rule::erase_rules(
					$data,
					W3TC_MARKER_BEGIN_PGCACHE_WPSC,
					W3TC_MARKER_END_PGCACHE_WPSC );
				$modified = true;
			}
		}

		if ( empty( $rules ) ) {
			// rules removal mode
			$rules_present = ( strpos( $data, $start ) !== false );
			if ( !$modified && !$rules_present ) {
				return;
			}
		} else {
			// rules creation mode
			$rules_missing = ( strstr( Util_Rule::clean_rules( $data ), Util_Rule::clean_rules( $rules ) ) === false );
			if ( !$modified && !$rules_missing ) {
				return;
			}
		}

		$replace_start = strpos( $data, $start );
		$replace_end = strpos( $data, $end );

		if ( $replace_start !== false && $replace_end !== false && $replace_start < $replace_end ) {
			// old rules exists, replace mode
			$replace_length = $replace_end - $replace_start + strlen( $end ) + 1;
		} else {
			$replace_start = false;
			$replace_length = 0;

			$search = $order;

			foreach ( $search as $string => $length ) {
				$replace_start = strpos( $data, $string );

				if ( $replace_start !== false ) {
					$replace_start += $length;
					break;
				}
			}
		}

		if ( $replace_start !== false ) {
			$data = Util_Rule::trim_rules( substr_replace( $data, $rules, $replace_start, $replace_length ) );
		} else {
			$data = Util_Rule::trim_rules( rtrim( $data ) . "\n" . $rules );
		}

		if ( strpos( $path, W3TC_CACHE_DIR ) === false || Util_Environment::is_nginx() ) {
			// writing to system rules file, may be potentially write-protected
			try {
				Util_WpFile::write_to_file( $path, $data );
			} catch ( Util_WpFile_FilesystemOperationException $ex ) {
				if ( $replace_start !== false ) {
					$message = sprintf( __( 'Edit file <strong>%s</strong> and replace all lines between and including <strong>%s</strong> and <strong>%s</strong> markers with:',
						'w3-total-cache' ), $path, $start, $end );
				} else {
					$message = sprintf( __( 'Edit file <strong>%s</strong> and add the following rules above the WordPress directives:',
						'w3-total-cache' ), $path );
				}

				$ex = new Util_WpFile_FilesystemModifyException(
					$ex->getMessage(), $ex->credentials_form(),
					$message, $path, $rules );

				$exs->push( $ex );
				return;
			}
		} else {
			// writing to own rules file in cache folder
			if ( !@file_exists( dirname( $path ) ) ) {
				Util_File::mkdir_from( dirname( $path ), W3TC_CACHE_DIR );
			}

			if ( !@file_put_contents( $path, $data ) ) {
				try {
					Util_WpFile::delete_folder(
						dirname( $path ),
						'',
						isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : ''
					);
				} catch ( Util_WpFile_FilesystemOperationException $ex ) {
					$exs->push( $ex );
					return;
				}
			}
		}

		Util_Rule::after_rules_modified();
	}



	/**
	 * Called when rules are modified, sets notification
	 */
	static public function after_rules_modified() {
		if ( Util_Environment::is_nginx() ) {
			$state = Dispatcher::config_state_master();
			$state->set( 'common.show_note.nginx_restart_required', true );
			$state->save();
		}
	}



	/**
	 * Remove rules
	 */
	static public function remove_rules( $exs, $path, $start, $end ) {
		if ( !file_exists( $path ) )
			return;

		$data = @file_get_contents( $path );
		if ( $data === false )
			return;
		if ( strstr( $data, $start ) === false )
			return;

		$data = Util_Rule::erase_rules( $data, $start,
			$end );

		try {
			Util_WpFile::write_to_file( $path, $data );
		} catch ( Util_WpFile_FilesystemOperationException $ex ) {
			$exs->push( new Util_WpFile_FilesystemModifyException(
					$ex->getMessage(), $ex->credentials_form(),
					sprintf( __( 'Edit file <strong>%s</strong> and remove all lines between and including <strong>%s</strong>
				and <strong>%s</strong> markers.', 'w3-total-cache' ), $path, $start, $end ), $path ) );
		}
	}

	/**
	 * Returns path of pgcache cache rules file
	 * Moved to separate file to not load rule.php for each disk enhanced request
	 *
	 * @return string
	 */
	static public function get_pgcache_rules_cache_path() {
		switch ( true ) {
		case Util_Environment::is_apache():
		case Util_Environment::is_litespeed():
			if ( Util_Environment::is_wpmu() ) {
				$url = get_home_url();
				$match = null;
				if ( preg_match( '~http(s)?://(.+?)(/)?$~', $url, $match ) ) {
					$home_path = $match[2];

					return W3TC_CACHE_PAGE_ENHANCED_DIR . DIRECTORY_SEPARATOR .
						$home_path . DIRECTORY_SEPARATOR . '.htaccess';
				}
			}

			return W3TC_CACHE_PAGE_ENHANCED_DIR . DIRECTORY_SEPARATOR . '.htaccess';

		case Util_Environment::is_nginx():
			return Util_Rule::get_nginx_rules_path();
		}

		return false;
	}

	/**
	 * Returns true if we can check rules
	 *
	 * @return bool
	 */
	static public function can_check_rules() {
		return Util_Environment::is_apache() ||
			Util_Environment::is_litespeed() ||
			Util_Environment::is_nginx() ||
			Util_Environment::is_iis();
	}

	/**
	 * Support for GoDaddy servers configuration which uses.
	 * SUBDOMAIN_DOCUMENT_ROOT variable.
	 */
	public static function apache_docroot_variable() {
		$document_root           = isset( $_SERVER['DOCUMENT_ROOT'] ) ? esc_url_raw( wp_unslash( $_SERVER['DOCUMENT_ROOT'] ) ) : '';
		$subdomain_document_root = isset( $_SERVER['SUBDOMAIN_DOCUMENT_ROOT'] ) ? esc_url_raw( wp_unslash( $_SERVER['SUBDOMAIN_DOCUMENT_ROOT'] ) ) : '';
		$php_document_root       = isset( $_SERVER['PHP_DOCUMENT_ROOT'] ) ? esc_url_raw( wp_unslash( $_SERVER['PHP_DOCUMENT_ROOT'] ) ) : '';
		if ( ! empty( $subdomain_document_root ) && $subdomain_document_root !== $document_root ) {
			return '%{ENV:SUBDOMAIN_DOCUMENT_ROOT}';
		} elseif ( ! empty( $php_document_root ) && $php_document_root !== $document_root ) {
			return '%{ENV:PHP_DOCUMENT_ROOT}';
		} else {
			return '%{DOCUMENT_ROOT}';
		}
	}



	/**
	 * Takes an array of extensions single per row and/or extensions delimited by |
	 *
	 * @param unknown $extensions
	 * @param unknown $ext
	 * @return array
	 */
	static public function remove_extension_from_list( $extensions, $ext ) {
		for ( $i = 0; $i < sizeof( $extensions ); $i++ ) {
			if ( $extensions[$i] == $ext ) {
				unset( $extensions[$i] );
				return $extensions;
			} elseif ( strpos( $extensions[$i], $ext ) !== false &&
				strpos( $extensions[$i], '|' ) !== false ) {
				$exts = explode( '|', $extensions[$i] );
				$key = array_search( $ext, $exts );
				unset( $exts[$key] );
				$extensions[$i] = implode( '|', $exts );
				return $extensions;
			}
		}
		return $extensions;
	}
}
