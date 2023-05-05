<?php
namespace W3TC;



class Generic_AdminActions_Test {

	private $_config = null;

	/**
	 * Current page
	 *
	 * @var null|string
	 */
	private $_page = null;

	function __construct() {
		$this->_config = Dispatcher::config();

		$this->_page = Util_Admin::get_current_page();
	}


	/**
	 * Test memcached
	 *
	 * @return void
	 */
	function w3tc_test_memcached() {
		$servers = Util_Request::get_array( 'servers' );

		$this->respond_test_result( $this->is_memcache_available( $servers ) );
	}

	/**
	 * Test memcached.
	 */
	public function w3tc_test_redis() {
		$servers                 = Util_Request::get_array( 'servers' );
		$verify_tls_certificates = Util_Request::get_boolean('verify_tls_certificates', true );
		$password                = Util_Request::get_string('password', '');
		$dbid                    = Util_Request::get_integer( 'dbid', 0 );

		if ( count( $servers ) <= 0 ) {
			$success = false;
		} else {
			$success = true;

			foreach ( $servers as $server ) {
				@$cache = Cache::instance( // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					'redis',
					array(
						'servers'                 => $server,
						'verify_tls_certificates' => $verify_tls_certificates,
						'persistent'              => false,
						'password'                => $password,
						'dbid'                    => $dbid,
					)
				);

				if ( is_null( $cache ) ) {
					$success = false;
				}

				$test_string = sprintf( 'test_' . md5( time() ) );
				$test_value  = array( 'content' => $test_string );

				$cache->set( $test_string, $test_value, 60 );

				$test_value = $cache->get( $test_string );

				if ( isset( $test_value['content'] ) && $test_value['content'] !== $test_string ) {
					$success = false;
				}
			}
		}

		$this->respond_test_result( $success );
	}

	private function respond_test_result( $success ) {
		if ( $success ) {
			$response = array(
				'result' => true,
				'error' => __( 'Test passed.', 'w3-total-cache' )
			);
		} else {
			$response = array(
				'result' => false,
				'error' => __( 'Test failed.', 'w3-total-cache' )
			);
		}

		echo wp_json_encode( $response );
		exit();
	}

	/**
	 * Test minifier action
	 *
	 * @return void
	 */
	function w3tc_test_minifier() {
		$engine = Util_Request::get_string( 'engine' );
		$path_java = Util_Request::get_string( 'path_java' );
		$path_jar = Util_Request::get_string( 'path_jar' );

		$result = false;
		$error = '';

		if ( $engine != 'googleccjs' ) {
			if ( !$path_java )
				$error = __( 'Empty JAVA executable path.', 'w3-total-cache' );
			elseif ( !$path_jar )
				$error = __( 'Empty JAR file path.', 'w3-total-cache' );
		}

		if ( empty( $error ) ) {
			switch ( $engine ) {
			case 'yuijs':
				\W3TCL\Minify\Minify_YUICompressor::$tempDir = Util_File::create_tmp_dir();
				\W3TCL\Minify\Minify_YUICompressor::$javaExecutable = $path_java;
				\W3TCL\Minify\Minify_YUICompressor::$jarFile = $path_jar;

				$result = \W3TCL\Minify\Minify_YUICompressor::testJs( $error );
				break;

			case 'yuicss':
				\W3TCL\Minify\Minify_YUICompressor::$tempDir = Util_File::create_tmp_dir();
				\W3TCL\Minify\Minify_YUICompressor::$javaExecutable = $path_java;
				\W3TCL\Minify\Minify_YUICompressor::$jarFile = $path_jar;

				$result = \W3TCL\Minify\Minify_YUICompressor::testCss( $error );
				break;

			case 'ccjs':
				\W3TCL\Minify\Minify_ClosureCompiler::$tempDir = Util_File::create_tmp_dir();
				\W3TCL\Minify\Minify_ClosureCompiler::$javaExecutable = $path_java;
				\W3TCL\Minify\Minify_ClosureCompiler::$jarFile = $path_jar;

				$result = \W3TCL\Minify\Minify_ClosureCompiler::test( $error );
				break;

			case 'googleccjs':

				$result = \W3TCL\Minify\Minify_JS_ClosureCompiler::test( $error );
				break;

			default:
				$error = __( 'Invalid engine.', 'w3-total-cache' );
				break;
			}
		}

		$response = array(
			'result' => $result,
			'error' => $error
		);

		echo json_encode( $response );
	}

	/**
	 * Check if memcache is available
	 *
	 * @param array   $servers
	 * @return boolean
	 */
	private function is_memcache_available( $servers ) {
		if ( count( $servers ) <= 0 )
			return false;

		foreach ( $servers as $server ) {
			@$memcached = Cache::instance( 'memcached', array(
					'servers' => $server,
					'persistent' => false
				) );
			if ( is_null( $memcached ) )
				return false;

			$test_string = sprintf( 'test_' . md5( time() ) );
			$test_value = array( 'content' => $test_string );
			$memcached->set( $test_string, $test_value, 60 );
			$test_value = $memcached->get( $test_string );
			if ( $test_value['content'] != $test_string )
				return false;
		}

		return true;
	}

	/**
	 * Self test action
	 */
	function w3tc_test_self() {
		include W3TC_INC_LIGHTBOX_DIR . '/self_test.php';
	}

	/**
	 * Minify recommendations action
	 *
	 * @return void
	 */
	function w3tc_test_minify_recommendations() {
		$options_minify = new Minify_Page();
		$options_minify->recommendations();
	}
}
