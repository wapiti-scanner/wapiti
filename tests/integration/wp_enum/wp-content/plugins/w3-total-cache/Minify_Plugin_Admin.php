<?php
namespace W3TC;



class Minify_Plugin_Admin {
	private $_config = null;

	function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Runs plugin
	 */
	function run() {
		add_filter( 'w3tc_save_options', array( $this, 'w3tc_save_options' ) );

		$config_labels = new Minify_ConfigLabels();
		add_filter( 'w3tc_config_labels', array( $config_labels, 'config_labels' ) );

		if ( $this->_config->get_boolean( 'minify.enabled' ) ) {
			add_filter( 'w3tc_usage_statistics_summary_from_history', array(
					$this, 'w3tc_usage_statistics_summary_from_history' ), 10, 2 );
			add_filter( 'w3tc_notes', array( $this, 'w3tc_notes' ) );
			add_filter( 'w3tc_errors', array( $this, 'w3tc_errors' ) );
		}

		add_action( 'w3tc_ajax_minify_help', array(
				$this,
				'w3tc_ajax_minify_help'
			) );
		add_action( 'w3tc_message_action_minify_help', array(
				$this,
				'w3tc_message_action_minify_help'
			) );

		if ( defined( 'W3TC_DEBUG' ) && W3TC_DEBUG )
			add_filter( 'w3tc_admin_bar_menu', array( $this, 'w3tc_admin_bar_menu' ) );

	}



	public function w3tc_admin_bar_menu( $menu_items ) {
		$menu_items['90040.minify'] = array(
			'id' => 'w3tc_overlay_minify',
			'parent' => 'w3tc_debug_overlays',
			'title' => __( 'Minify', 'w3-total-cache' ),
			'href' => wp_nonce_url( network_admin_url(
					'admin.php?page=w3tc_dashboard&amp;w3tc_message_action=minify_help' ), 'w3tc' )
		);

		return $menu_items;
	}



	public function w3tc_message_action_minify_help() {
		wp_enqueue_script( 'w3tc-minify-help',
			plugins_url( 'Minify_GeneralPage_View_ShowHelp.js', W3TC_FILE ),
			array(), W3TC_VERSION );
		wp_enqueue_script( 'w3tc-minify-help-force',
			plugins_url( 'Minify_GeneralPage_View_ShowHelpForce.js', W3TC_FILE ),
			array(), W3TC_VERSION );
	}



	public function w3tc_save_options( $data ) {
		$new_config = $data['new_config'];
		$old_config = $data['old_config'];

		if ( $new_config->get_boolean( 'minify.enabled' ) &&
			!$old_config->get_boolean( 'minify.enabled' ) ) {

			$state = Dispatcher::config_state();
			$state->set( 'minify.hide_minify_help', true );
			$state->save();

		}

		return $data;
	}



	public static function admin_print_scripts_w3tc_general() {
		$state = Dispatcher::config_state();
		if ( !$state->get_boolean( 'minify.hide_minify_help' ) ) {
			wp_enqueue_script( 'w3tc-minify-help',
				plugins_url( 'Minify_GeneralPage_View_ShowHelp.js', W3TC_FILE ),
				array(), W3TC_VERSION );
		}
	}



	/**
	 * Does disk cache cleanup
	 *
	 * @return void
	 */
	function cleanup() {
		$w3_cache_file_cleaner_generic = new Cache_File_Cleaner_Generic( array(
				'exclude' => array(
					'*.files',
					'.htaccess',
					'index.html'
				),
				'cache_dir' => Util_Environment::cache_blog_dir( 'minify' ),
				'expire' => $this->_config->get_integer( 'minify.file.gc' ),
				'clean_timelimit' => $this->_config->get_integer( 'timelimit.cache_gc' )
			) );

		$w3_cache_file_cleaner_generic->clean();
	}

	function w3tc_errors( $errors ) {
		$c = Dispatcher::config();
		$state = Dispatcher::config_state_master();

		/**
		 * Minify error occured
		 */
		if ( $state->get_boolean( 'minify.show_note_minify_error' ) ) {
			$errors['minify_error_creating'] = sprintf(
				__( 'Recently an error occurred while creating the CSS / JS minify cache: %s. %s',
					'w3-total-cache' ),
				$state->get_string( 'minify.error.last' ),
				Util_Ui::button_hide_note2( array(
						'w3tc_default_config_state_master' => 'y',
						'key' => 'minify.show_note_minify_error',
						'value' => 'false' ) ) );
		}

		if ( $c->get_string( 'minify.engine' ) == 'memcached' ) {
			$memcached_servers = $c->get_array( 'minify.memcached.servers' );

			if ( !Util_Installed::is_memcache_available( $memcached_servers ) ) {
				if ( !isset( $errors['memcache_not_responding.details'] ) )
					$errors['memcache_not_responding.details'] = array();

				$errors['memcache_not_responding.details'][] = sprintf(
					__( 'Minify: %s.', 'w3-total-cache' ),
					implode( ', ', $memcached_servers ) );
			}
		}

		return $errors;
	}

	function w3tc_notes( $notes ) {
		$state_note = Dispatcher::config_state();
		/**
		 * Show notification when minify needs to be emptied
		 */
		if ( $state_note->get_boolean( 'minify.show_note.need_flush' ) &&
			!is_network_admin() /* flushing doesnt work in network admin */ &&
			!$this->_config->is_preview() ) {
			$notes['minify_flush_needed'] = sprintf(
				__( 'The setting change(s) made either invalidate the cached data or modify the behavior of the site. %s now to provide a consistent user experience.',
					'w3-total-cache' ),
				Util_Ui::button_link(
					__( 'Empty the minify cache', 'w3-total-cache' ),
					Util_Ui::url( array( 'w3tc_flush_minify' => 'y' ) ) ) );
		}

		return $notes;
	}



	public function w3tc_ajax_minify_help() {
		include  W3TC_DIR . '/Minify_HelpPopup_View.php';
	}



	public function w3tc_usage_statistics_summary_from_history( $summary, $history ) {
		// memcached servers
		$c = Dispatcher::config();
		if ( $c->get_string( 'minify.engine' ) == 'memcached' ) {
			$summary['memcached_servers']['minify'] = array(
				'servers' => $c->get_array( 'minify.memcached.servers' ),
				'username' => $c->get_string( 'minify.memcached.username' ),
				'password' => $c->get_string( 'minify.memcached.password' ),
				'binary_protocol' => $c->get_boolean( 'minify.memcached.binary_protocol' ),
				'name' => __( 'Minification', 'w3-total-cache' )
			);
		} elseif ( $c->get_string( 'minify.engine' ) == 'redis' ) {
			$summary['redis_servers']['minify'] = array(
				'servers' => $c->get_array( 'minify.redis.servers' ),
				'username' => $c->get_boolean( 'minify.redis.username' ),
				'dbid' => $c->get_integer( 'minify.redis.dbid' ),
				'password' => $c->get_string( 'minify.redis.password' ),
				'name' => __( 'Minification', 'w3-total-cache' )
			);
		}

		$e = $this->_config->get_string( 'minify.engine' );
		$a = array(
			'size_visible' => ( $e == 'file' ),
			'requests_visible' =>
			!( $e == 'file' && $this->_config->get_boolean( 'minify.rewrite' ) )
		);

		if ( !isset( $summary['period']['timestamp_end'] ) ) {
			// summary requested, enough
			$summary['minify'] = $a;
			return $summary;
		}

		// get requests rate stats
		if ( $a['requests_visible'] ) {
			// counters
			$requests_total = Util_UsageStatistics::sum( $history,
				'minify_requests_total' );
			$original_length_css = Util_UsageStatistics::sum( $history,
				'minify_original_length_css' );
			$output_length_css = Util_UsageStatistics::sum( $history,
				'minify_output_length_css' );

			$original_length_js = Util_UsageStatistics::sum( $history,
				'minify_original_length_js' );
			$output_length_js = Util_UsageStatistics::sum( $history,
				'minify_output_length_js' );

			$a['requests_total'] = Util_UsageStatistics::integer(
				$requests_total );
			$a['requests_per_second'] =
				Util_UsageStatistics::value_per_period_seconds(
				$requests_total, $summary );
			$a['compression_css'] = Util_UsageStatistics::percent(
				$original_length_css - $output_length_css, $original_length_css );
			$a['compression_js'] = Util_UsageStatistics::percent(
				$original_length_js - $output_length_js, $original_length_js );
		}
		if ( $a['size_visible'] ) {
			list( $v, $should_count ) =
				Util_UsageStatistics::get_or_init_size_transient(
				'w3tc_ustats_minify_size', $summary );
			if ( $should_count ) {
				$h = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );
				$stats = $h->get_stats_size( $summary['timeout_time'] );

				// build stats to show
				$v['size_used'] = Util_UsageStatistics::bytes_to_size(
					$stats['css']['output_length'] + $stats['js']['output_length'] );
				$v['size_items'] = Util_UsageStatistics::integer(
					$stats['css']['items'] + $stats['js']['items'] );
				$v['size_compression_css'] = Util_UsageStatistics::percent(
					$stats['css']['original_length'] - $stats['css']['output_length'],
					$stats['css']['original_length'] );
				$v['size_compression_js'] = Util_UsageStatistics::percent(
					$stats['js']['original_length'] - $stats['js']['output_length'],
					$stats['js']['original_length'] );

				set_transient( 'w3tc_ustats_pagecache_size', $v, 120 );
			}

			if ( isset( $v['size_used'] ) ) {
				$a['size_used'] = $v['size_used'];
				$a['size_items'] = $v['size_items'];
				$a['size_compression_css'] = $v['size_compression_css'];
				$a['size_compression_js'] = $v['size_compression_js'];
			}
		}

		$summary['minify'] = $a;
		return $summary;
	}
}
