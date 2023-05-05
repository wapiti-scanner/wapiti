<?php
namespace W3TC;



/**
 * class Root_Environment
 */
class Root_Environment {
	/**
	 * Fixes environment
	 *
	 * @param Config  $config
	 * @throws Util_Environment_Exceptions
	 */
	function fix_in_wpadmin( $config, $force_all_checks = false ) {
		$exs = new Util_Environment_Exceptions();
		$fix_on_event = false;
		if ( Util_Environment::is_wpmu() && Util_Environment::blog_id() != 0 ) {
			if ( get_transient( 'w3tc_config_changes' ) != ( $md5_string = $config->get_md5() ) ) {
				$fix_on_event = true;
				set_transient( 'w3tc_config_changes', $md5_string, 3600 );
			}
		}
		// call plugin-related handlers
		foreach ( $this->get_handlers() as $h ) {
			try {
				$h->fix_on_wpadmin_request( $config, $force_all_checks );
				if ( $fix_on_event ) {
					$this->fix_on_event( $config, 'admin_request' );
				}
			} catch ( Util_Environment_Exceptions $ex ) {
				$exs->push( $ex );
			}
		}

		try {
			do_action( 'w3tc_environment_fix_on_wpadmin_request',
				$config, $force_all_checks );
		} catch ( Util_Environment_Exceptions $ex ) {
			$exs->push( $ex );
		}

		if ( count( $exs->exceptions() ) > 0 )
			throw $exs;
	}

	/**
	 * Fixes environment once event occurs
	 *
	 * @throws Util_Environment_Exceptions
	 */
	public function fix_on_event( $config, $event, $old_config = null ) {
		$exs = new Util_Environment_Exceptions();

		// call plugin-related handlers
		foreach ( $this->get_handlers() as $h ) {
			try {
				$h->fix_on_event( $config, $event );
			} catch ( Util_Environment_Exceptions $ex ) {
				$exs->push( $ex );
			}
		}

		try {
			do_action( 'w3tc_environment_fix_on_event',
				$config, $event );
		} catch ( Util_Environment_Exceptions $ex ) {
			$exs->push( $ex );
		}

		if ( count( $exs->exceptions() ) > 0 )
			throw $exs;
	}

	/**
	 * Fixes environment after plugin deactivation
	 *
	 * @param Config  $config
	 * @throws Util_Environment_Exceptions
	 */
	public function fix_after_deactivation() {
		$exs = new Util_Environment_Exceptions();

		// call plugin-related handlers
		foreach ( $this->get_handlers() as $h ) {
			try {
				$h->fix_after_deactivation();
			} catch ( Util_Environment_Exceptions $ex ) {
				$exs->push( $ex );
			}
		}

		try {
			do_action( 'w3tc_environment_fix_after_deactivation' );
		} catch ( Util_Environment_Exceptions $ex ) {
			$exs->push( $ex );
		}

		if ( count( $exs->exceptions() ) > 0 )
			throw $exs;
	}

	/**
	 * Returns an array[filename]=rules of rules for .htaccess or nginx files
	 *
	 * @param Config  $config
	 * @return array
	 */
	public function get_required_rules( $config ) {
		$required_rules = array();
		foreach ( $this->get_handlers() as $h ) {
			$required_rules_current = $h->get_required_rules( $config );

			if ( !is_null( $required_rules_current ) )
				$required_rules = array_merge( $required_rules, $required_rules_current );
		}

		$required_rules = apply_filters( 'w3tc_environment_get_required_rules',
			$required_rules, $config );


		$rewrite_rules_descriptors = array();

		foreach ( $required_rules as $descriptor ) {
			$filename = $descriptor['filename'];

			if ( isset( $rewrite_rules_descriptors[$filename] ) )
				$content = $rewrite_rules_descriptors[$filename]['content'];
			else
				$content = array();

			if ( !isset( $descriptor['position'] ) )
				$content[] = $descriptor['content'];
			else {
				$position = $descriptor['position'];

				if ( isset( $content[$position] ) )
					$content[$position] .= $descriptor['content'];
				else
					$content[$position] = $descriptor['content'];
			}

			$rewrite_rules_descriptors[$filename] = array(
				'filename' => $filename,
				'content' => $content
			);
		}

		$rewrite_rules_descriptors_out = array();
		foreach ( $rewrite_rules_descriptors as $filename => $descriptor ) {
			$rewrite_rules_descriptors_out[$filename] = array(
				'filename' => $filename,
				'content' => implode( '', $descriptor['content'] )
			);
		}
		ksort( $rewrite_rules_descriptors_out );
		return $rewrite_rules_descriptors_out;
	}

	/**
	 * Returns plugin-related environment handlers
	 *
	 * @param Config  $config
	 * @return array
	 */
	private function get_handlers() {
		$a = array(
			new Generic_Environment(),
			new Minify_Environment(),
			new PgCache_Environment(),
			new BrowserCache_Environment(),
			new ObjectCache_Environment(),
			new DbCache_Environment(),
			new Cdn_Environment(),
			new Extension_ImageService_Environment(),
		);

		return $a;
	}

	public function get_other_instructions( $config ) {
		$instructions_descriptors = array();

		foreach ( $this->get_handlers() as $h ) {
			if ( method_exists( $h, 'get_instructions' ) ) {
				$instructions = $h->get_instructions( $config );
				if ( !is_null( $instructions ) ) {
					foreach ( $instructions as $descriptor ) {
						$area = $descriptor['area'];
						$instructions_descriptors[$area][] = array(
							'title' => $descriptor['title'],
							'content' => $descriptor['content']
						);
					}
				}
			}

		}
		return $instructions_descriptors;
	}
}
