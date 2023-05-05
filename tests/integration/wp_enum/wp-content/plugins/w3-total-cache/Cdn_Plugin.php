<?php
/**
 * File: Cdn_Plugin.php
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: Cdn_Plugin
 *
 * phpcs:disable PSR2.Classes.PropertyDeclaration.Underscore
 * phpcs:disable PSR2.Methods.MethodDeclaration.Underscore
 */
class Cdn_Plugin {
	/**
	 * Reject reason.
	 *
	 * @var string
	 */
	private $cdn_reject_reason = '';

	/**
	 * Config.
	 *
	 * @var Config
	 */
	private $_config = null;

	/**
	 * Debug flag.
	 *
	 * @var bool
	 */
	private $_debug = false;

	/**
	 * Attachements action.
	 *
	 * @var array
	 */
	private $_attachments_action = array();

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->_config = Dispatcher::config();
		$this->_debug  = $this->_config->get_boolean( 'cdn.debug' );
	}

	/**
	 * Runs plugin
	 */
	public function run() {
		$cdn_engine = $this->_config->get_string( 'cdn.engine' );

		add_filter( 'cron_schedules', array( $this, 'cron_schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval.ChangeDetected
		add_filter( 'w3tc_footer_comment', array( $this, 'w3tc_footer_comment' ) );

		if ( ! Cdn_Util::is_engine_mirror( $cdn_engine ) ) {
			add_action( 'w3_cdn_cron_queue_process', array( $this, 'cron_queue_process' ) );
			add_action( 'w3_cdn_cron_upload', array( $this, 'cron_upload' ) );
			add_action( 'switch_theme', array( $this, 'switch_theme' ) );

			add_filter( 'update_feedback', array( $this, 'update_feedback' ) );
		}

		$default_override = Cdn_Util::get_flush_manually_default_override( $cdn_engine );
		$flush_on_actions = ! $this->_config->get_boolean( 'cdn.flush_manually', $default_override );

		if ( $flush_on_actions ) {
			add_action( 'delete_attachment', array( $this, 'delete_attachment' ) );
			add_filter( 'wp_insert_attachment_data', array( $this, 'check_inserting_new_attachment' ), 10, 2 );
			add_filter( 'update_attached_file', array( $this, 'update_attached_file' ) );
			add_filter( 'wp_update_attachment_metadata', array( $this, 'update_attachment_metadata' ) );
		}

		add_filter( 'w3tc_preflush_cdn_all', array( $this, 'w3tc_preflush_cdn_all' ), 10, 2 );
		add_filter( 'w3tc_admin_bar_menu', array( $this, 'w3tc_admin_bar_menu' ) );

		if ( is_admin() ) {
			add_filter( 'w3tc_module_is_running-cdn', array( $this, 'cdn_is_running' ) );
		}

		if ( ! is_admin() || $this->_config->get_boolean( 'cdn.admin.media_library' ) ) {
			add_filter( 'wp_prepare_attachment_for_js', array( $this, 'wp_prepare_attachment_for_js' ), 0 );
		}

		// Start rewrite engine.
		if ( $this->can_cdn() ) {
			Util_Bus::add_ob_callback( 'cdn', array( $this, 'ob_callback' ) );
		}

		if ( is_admin() && Cdn_Util::can_purge( $cdn_engine ) ) {
			add_filter( 'media_row_actions', array( $this, 'media_row_actions' ), 0, 2 );
		}

		add_filter( 'w3tc_minify_http2_preload_url', array( $this, 'w3tc_minify_http2_preload_url' ), 3000 );
	}

	/**
	 * Instantiates worker with admin functionality on demand
	 *
	 * @return Cdn_Core_Admin
	 */
	public function get_admin() {
		return Dispatcher::component( 'Cdn_Core_Admin' );
	}

	/**
	 * Cron queue process event
	 */
	public function cron_queue_process() {
		$queue_limit = $this->_config->get_integer( 'cdn.queue.limit' );
		return $this->get_admin()->queue_process( $queue_limit );
	}

	/**
	 * Cron upload event
	 */
	public function cron_upload() {
		$files = $this->get_files();

		$upload  = array();
		$results = array();

		$common = Dispatcher::component( 'Cdn_Core' );

		foreach ( $files as $file ) {
			$local_path  = $common->docroot_filename_to_absolute_path( $file );
			$remote_path = $common->uri_to_cdn_uri( $common->docroot_filename_to_uri( $file ) );
			$upload[]    = $common->build_file_descriptor( $local_path, $remote_path );
		}

		$common->upload( $upload, true, $results );
	}

	/**
	 * Check attachement insert
	 *
	 * @param array $data Attachement processed data.
	 * @param array $postarr Attachement un-processed data.
	 *
	 * @return array
	 */
	public function check_inserting_new_attachment( $data, $postarr ) {
		$this->_attachments_action[ $postarr['file'] ] = empty( $postarr['ID'] ) ? 'insert' : 'update';

		return $data;
	}

	/**
	 * Preflush CDN.
	 *
	 * @param bool  $do_flush Flush flag.
	 * @param array $extras Extras.
	 *
	 * @return bool
	 */
	public function w3tc_preflush_cdn_all( $do_flush, $extras = array() ) {
		$default_override = Cdn_Util::get_flush_manually_default_override( $this->_config->get_string( 'cdn.engine' ) );
		if ( $this->_config->get_boolean( 'cdn.flush_manually', $default_override ) ) {
			if ( ! isset( $extras['ui_action'] ) ) {
				$do_flush = false;
			}
		}

		return $do_flush;
	}

	/**
	 * Update attachment file
	 *
	 * Upload _wp_attached_file
	 *
	 * @param string $attached_file Attchement file path.
	 *
	 * @return string
	 */
	public function update_attached_file( $attached_file ) {
		$common = Dispatcher::component( 'Cdn_Core' );
		$files  = $common->get_files_for_upload( $attached_file );
		$files  = apply_filters( 'w3tc_cdn_update_attachment', $files );

		$results = array();

		$cdn_engine = $this->_config->get_string( 'cdn.engine' );
		if ( Cdn_Util::is_engine_mirror( $cdn_engine ) ) {
			if ( ! array_key_exists( $attached_file, $this->_attachments_action ) || 'update' === $this->_attachments_action[ $attached_file ] ) {
				$common->purge( $files, $results );
			}
		} else {
			$common->upload( $files, true, $results );
		}

		return $attached_file;
	}

	/**
	 * On attachment delete action
	 *
	 * Delete _wp_attached_file, _wp_attachment_metadata, _wp_attachment_backup_sizes
	 *
	 * @param integer $attachment_id Attchement ID.
	 */
	public function delete_attachment( $attachment_id ) {
		$common = Dispatcher::component( 'Cdn_Core' );
		$files  = $common->get_attachment_files( $attachment_id );
		$files  = apply_filters( 'w3tc_cdn_delete_attachment', $files );

		$results = array();

		$cdn_engine = $this->_config->get_string( 'cdn.engine' );
		if ( Cdn_Util::is_engine_mirror( $cdn_engine ) ) {
			$common->purge( $files, $results );
		} else {
			$common->delete( $files, true, $results );
		}
	}

	/**
	 * Update attachment metadata filter
	 *
	 * Upload _wp_attachment_metadata
	 *
	 * @param array $metadata Metadata.
	 *
	 * @return array
	 */
	public function update_attachment_metadata( $metadata ) {
		$common = Dispatcher::component( 'Cdn_Core' );
		$files  = $common->get_metadata_files( $metadata );
		$files  = apply_filters( 'w3tc_cdn_update_attachment_metadata', $files );

		$results = array();

		$cdn_engine = $this->_config->get_string( 'cdn.engine' );
		if ( Cdn_Util::is_engine_mirror( $cdn_engine ) ) {
			if ( $this->_config->get_boolean( 'cdn.uploads.enable' ) ) {
				$common->purge( $files, $results );
			}
		} else {
			$common->upload( $files, true, $results );
		}

		return $metadata;
	}

	/**
	 * Cron schedules filter
	 *
	 * @param array $schedules Schedules.
	 *
	 * @return array
	 */
	public function cron_schedules( $schedules ) {
		$c = $this->_config;

		if ( $c->get_boolean( 'cdn.enabled' ) && ! Cdn_Util::is_engine_mirror( $c->get_string( 'cdn.engine' ) ) ) {
			$queue_interval = $c->get_integer( 'cdn.queue.interval' );

			$schedules['w3_cdn_cron_queue_process'] = array(
				'interval' => $queue_interval,
				'display'  => sprintf(
					// translators: 1 queue interval value.
					__(
						'[W3TC] CDN queue process (every %1$d seconds)',
						'w3-total-cache'
					),
					$queue_interval
				),
			);
		}

		if ( $c->get_boolean( 'cdn.enabled' ) &&
			$c->get_boolean( 'cdn.autoupload.enabled' ) &&
			! Cdn_Util::is_engine_mirror( $c->get_string( 'cdn.engine' ) ) ) {
			$autoupload_interval = $c->get_integer( 'cdn.autoupload.interval' );

			$schedules['w3_cdn_cron_upload'] = array(
				'interval' => $autoupload_interval,
				'display'  => sprintf(
					// translators: 1 queue interval value.
					__(
						'[W3TC] CDN auto upload (every %1$d seconds)',
						'w3-total-cache'
					),
					$autoupload_interval
				),
			);
		}

		return $schedules;
	}

	/**
	 * Switch theme action.
	 */
	public function switch_theme() {
		$state = Dispatcher::config_state();
		$state->set( 'cdn.show_note_theme_changed', true );
		$state->save();
	}

	/**
	 * WP Upgrade action hack.
	 *
	 * @param string $message Message.
	 */
	public function update_feedback( $message ) {
		if ( 'Upgrading database' === $message ) {
			$state = Dispatcher::config_state();
			$state->set( 'cdn.show_note_wp_upgraded', true );
			$state->save();
		}
	}

	/**
	 * OB Callback.
	 *
	 * @param string $buffer Buffer.
	 *
	 * @return string
	 */
	public function ob_callback( $buffer ) {
		if ( '' !== $buffer && Util_Content::is_html_xml( $buffer ) ) {
			if ( $this->can_cdn2( $buffer ) ) {
				$srcset_helper = new _Cdn_Plugin_ContentFilter();
				$buffer        = $srcset_helper->replace_all_links( $buffer );

				if ( $this->_debug ) {
					$replaced_urls = $srcset_helper->get_replaced_urls();
					$buffer        = $this->w3tc_footer_comment_after( $buffer, $replaced_urls );
				}
			}
		}

		return $buffer;
	}

	/**
	 * Returns array of files to upload.
	 *
	 * @return array
	 */
	public function get_files() {
		$files = array();

		if ( $this->_config->get_boolean( 'cdn.includes.enable' ) ) {
			$files = array_merge( $files, $this->get_files_includes() );
		}

		if ( $this->_config->get_boolean( 'cdn.theme.enable' ) ) {
			$files = array_merge( $files, $this->get_files_theme() );
		}

		if ( $this->_config->get_boolean( 'cdn.minify.enable' ) ) {
			$files = array_merge( $files, $this->get_files_minify() );
		}

		if ( $this->_config->get_boolean( 'cdn.custom.enable' ) ) {
			$files = array_merge( $files, $this->get_files_custom() );
		}

		return $files;
	}

	/**
	 * Exports includes to CDN
	 *
	 * @return array
	 */
	public function get_files_includes() {
		$includes_root = Util_Environment::normalize_path( ABSPATH . WPINC );
		$doc_root      = Util_Environment::normalize_path( Util_Environment::document_root() );
		$includes_path = ltrim( str_replace( $doc_root, '', $includes_root ), '/' );

		$files = Cdn_Util::search_files(
			$includes_root,
			$includes_path,
			$this->_config->get_string( 'cdn.includes.files' )
		);

		return $files;
	}

	/**
	 * Exports theme to CDN
	 *
	 * @return array
	 */
	public function get_files_theme() {
		// If mobile or referrer support enabled we should upload whole themes directory.
		if ( $this->_config->get_boolean( 'mobile.enabled' ) || $this->_config->get_boolean( 'referrer.enabled' ) ) {
			$themes_root = get_theme_root();
		} else {
			$themes_root = get_stylesheet_directory();
		}

		$themes_root = Util_Environment::normalize_path( $themes_root );
		$themes_path = ltrim( str_replace( Util_Environment::normalize_path( Util_Environment::document_root() ), '', $themes_root ), '/' );
		$files       = Cdn_Util::search_files(
			$themes_root,
			$themes_path,
			$this->_config->get_string( 'cdn.theme.files' )
		);

		return $files;
	}

	/**
	 * Exports min files to CDN.
	 *
	 * @return array
	 */
	public function get_files_minify() {
		$files = array();

		if ( $this->_config->get_boolean( 'minify.rewrite' ) &&
			Util_Rule::can_check_rules() &&
			(
				! $this->_config->get_boolean( 'minify.auto' ) ||
				Cdn_Util::is_engine_mirror( $this->_config->get_string( 'cdn.engine' ) )
			) ) {

			$minify = Dispatcher::component( 'Minify_Plugin' );

			$document_root = Util_Environment::normalize_path( Util_Environment::document_root() );
			$minify_root   = Util_Environment::normalize_path( Util_Environment::cache_blog_dir( 'minify' ) );
			$minify_path   = ltrim( str_replace( $document_root, '', $minify_root ), '/' );

			$urls = $minify->get_urls();

			// In WPMU + network admin (this code used for minify manual only)
			// common minify files are stored under context of main blog (i.e. 1)
			// but have urls of 0 blog, so download has to be used.
			if ( 'file' === $this->_config->get_string( 'minify.engine' ) && ! ( Util_Environment::is_wpmu() && is_network_admin() ) ) {
				foreach ( $urls as $url ) {
					Util_Http::get( $url );
				}

				$files = Cdn_Util::search_files(
					$minify_root,
					$minify_path,
					'*.css;*.js'
				);
			} else {
				foreach ( $urls as $url ) {
					$file = Util_Environment::normalize_file_minify( $url );

					if ( ! Util_Environment::is_url( $file ) ) {
						$file = $document_root . '/' . $file;
						$file = ltrim( str_replace( $minify_root, '', $file ), '/' );

						$dir = dirname( $file );

						if ( $dir ) {
							Util_File::mkdir( $dir, 0777, $minify_root );
						}

						if ( Util_Http::download( $url, $minify_root . '/' . $file ) !== false ) {
							$files[] = $minify_path . '/' . $file;
						}
					}
				}
			}
		}

		return $files;
	}

	/**
	 * Exports custom files to CDN
	 *
	 * @return array
	 */
	public function get_files_custom() {
		$files         = array();
		$document_root = Util_Environment::normalize_path( Util_Environment::document_root() );
		$custom_files  = $this->_config->get_array( 'cdn.custom.files' );
		$custom_files  = array_map( array( '\W3TC\Util_Environment', 'parse_path' ), $custom_files );
		$site_root     = Util_Environment::normalize_path( Util_Environment::site_root() );
		$path          = Util_Environment::site_url_uri();
		$site_root_dir = str_replace( $document_root, '', $site_root );
		if ( strstr( WP_CONTENT_DIR, Util_Environment::site_root() ) === false ) {
			$site_root = Util_Environment::normalize_path( Util_Environment::document_root() );
			$path      = '';
		}

		$content_path = trim( str_replace( WP_CONTENT_DIR, '', $site_root ), '/\\' );

		foreach ( $custom_files as $custom_file ) {
			if ( '' !== $custom_file ) {
				$custom_file = Cdn_Util::replace_folder_placeholders( $custom_file );
				$custom_file = Util_Environment::normalize_file( $custom_file );

				$dir      = trim( dirname( $custom_file ), '/\\' );
				$rel_path = $dir;

				if ( strpos( $dir, '<currentblog>' ) !== false ) {
					$dir      = str_replace( '<currentblog>', 'blogs.dir/' . Util_Environment::blog_id(), $dir );
					$rel_path = $dir;
				}

				if ( '.' === $dir ) {
					$dir      = '';
					$rel_path = $dir;
				}

				$mask  = basename( $custom_file );
				$files = array_merge(
					$files,
					Cdn_Util::search_files(
						$document_root . '/' . $dir,
						$rel_path,
						$mask
					)
				);
			}
		}

		return $files;
	}

	/**
	 * Check if we can do CDN logic
	 *
	 * @return boolean
	 */
	public function can_cdn() {
		// Skip if admin.
		if ( defined( 'WP_ADMIN' ) ) {
			$this->cdn_reject_reason = esc_html__( 'wp-admin', 'w3-total-cache' );

			return false;
		}

		// Check for WPMU's and WP's 3.0 short init.
		if ( defined( 'SHORTINIT' ) && SHORTINIT ) {
			$this->cdn_reject_reason = esc_html__( 'Short init', 'w3-total-cache' );

			return false;
		}

		// Check User agent.
		if ( ! $this->check_ua() ) {
			$this->cdn_reject_reason = esc_html__( 'user agent is rejected', 'w3-total-cache' );

			return false;
		}

		// Check request URI.
		if ( ! $this->_check_request_uri() ) {
			$this->cdn_reject_reason = esc_html__( 'request URI is rejected', 'w3-total-cache' );

			return false;
		}

		// Do not replace urls if SSL and SSL support is do not replace.
		if ( Util_Environment::is_https() && $this->_config->get_boolean( 'cdn.reject.ssl' ) ) {
			$this->cdn_reject_reason = esc_html__( 'SSL is rejected', 'w3-total-cache' );

			return false;
		}

		return true;
	}

	/**
	 * Returns true if we can do CDN logic
	 *
	 * @param unknown $buffer Buffer.
	 *
	 * @return string
	 */
	public function can_cdn2( $buffer ) {
		// Check for DONOTCDN constant.
		if ( defined( 'DONOTCDN' ) && DONOTCDN ) {
			$this->cdn_reject_reason = esc_html__( 'DONOTCDN constant is defined', 'w3-total-cache' );

			return false;
		}

		// Check logged users roles.
		if ( $this->_config->get_boolean( 'cdn.reject.logged_roles' ) && ! $this->_check_logged_in_role_allowed() ) {
			$this->cdn_reject_reason = esc_html__( 'logged in role is rejected', 'w3-total-cache' );

			return false;
		}

		return true;
	}

	/**
	 * Checks User Agent.
	 *
	 * @return boolean
	 */
	public function check_ua() {
		$uas = array_merge(
			$this->_config->get_array( 'cdn.reject.ua' ),
			array( W3TC_POWERED_BY )
		);

		foreach ( $uas as $ua ) {
			if ( ! empty( $ua ) ) {
				if ( isset( $_SERVER['HTTP_USER_AGENT'] ) && stristr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), $ua ) !== false ) {
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Checks request URI.
	 *
	 * @return boolean
	 */
	public function _check_request_uri() {
		$reject_uri = $this->_config->get_array( 'cdn.reject.uri' );
		$reject_uri = array_map( array( '\W3TC\Util_Environment', 'parse_path' ), $reject_uri );

		foreach ( $reject_uri as $expr ) {
			$expr = trim( $expr );
			$expr = str_replace( '~', '\~', $expr );

			if ( '' !== $expr && preg_match( '~' . $expr . '~i', isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' ) ) {
				return false;
			}
		}

		if ( Util_Request::get_string( 'wp_customize' ) ) {
			return false;
		}

		return true;
	}
	/**
	 * Check if logged in user role is allwed to use CDN
	 *
	 * @return boolean
	 */
	private function _check_logged_in_role_allowed() {
		$current_user = wp_get_current_user();

		if ( ! is_user_logged_in() ) {
			return true;
		}

		$roles = $this->_config->get_array( 'cdn.reject.roles' );

		if ( empty( $roles ) || empty( $current_user->roles ) || ! is_array( $current_user->roles ) ) {
			return true;
		}

		foreach ( $current_user->roles as $role ) {
			if ( in_array( $role, $roles, true ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Media row actions filter.
	 *
	 * @param array  $actions Actions.
	 * @param object $post Post.
	 *
	 * @return array
	 */
	public function media_row_actions( $actions, $post ) {
		return $this->get_admin()->media_row_actions( $actions, $post );
	}

	/**
	 * Get CDN running status.
	 *
	 * @param unknown $current_state Current state.
	 *
	 * @return bool
	 */
	public function cdn_is_running( $current_state ) {
		$admin = $this->get_admin();
		return $admin->is_running();
	}

	/**
	 * Change canonical header
	 */
	public function change_canonical_header() {
		$admin = $this->get_admin();
		$admin->change_canonical_header();
	}

	/**
	 * Adjusts attachment urls to cdn. This is for those who rely on wp_prepare_attachment_for_js().
	 *
	 * @param array $response Mixed collection of data about the attachment object.
	 *
	 * @return array
	 */
	public function wp_prepare_attachment_for_js( $response ) {
		$response['url']  = $this->wp_prepare_attachment_for_js_url( $response['url'] );
		$response['link'] = $this->wp_prepare_attachment_for_js_url( $response['link'] );

		if ( ! empty( $response['sizes'] ) ) {
			foreach ( $response['sizes'] as $size => &$data ) {
				$data['url'] = $this->wp_prepare_attachment_for_js_url( $data['url'] );
			}
		}

		return $response;
	}

	/**
	 * An attachment's local url to modify into a cdn url.
	 *
	 * @param string $url the local url to modify.
	 *
	 * @return string
	 */
	private function wp_prepare_attachment_for_js_url( $url ) {
		$url = trim( $url );
		if ( ! empty( $url ) ) {
			$parsed = wp_parse_url( $url );
			$uri    = ( isset( $parsed['path'] ) ? $parsed['path'] : '/' ) .
				( isset( $parsed['query'] ) ? '?' . $parsed['query'] : '' );

			$wp_upload_dir   = wp_upload_dir();
			$upload_base_url = $wp_upload_dir['baseurl'];

			if ( substr( $url, 0, strlen( $upload_base_url ) ) === $upload_base_url ) {
				$common  = Dispatcher::component( 'Cdn_Core' );
				$new_url = $common->url_to_cdn_url( $url, $uri );
				if ( ! is_null( $new_url ) ) {
					$url = $new_url;
				}
			}
		}

		return $url;
	}

	/**
	 * Mutate http/2 header links
	 *
	 * @param array $data Data.
	 */
	public function w3tc_minify_http2_preload_url( $data ) {
		$url = $data['result_link'];

		$url = trim( $url );
		if ( empty( $url ) ) {
			return $data;
		}

		$parsed = wp_parse_url( $url );
		$uri    = ( isset( $parsed['path'] ) ? $parsed['path'] : '/' ) .
			( isset( $parsed['query'] ) ? '?' . $parsed['query'] : '' );

		$common  = Dispatcher::component( 'Cdn_Core' );
		$new_url = $common->url_to_cdn_url( $url, $uri );
		if ( is_null( $new_url ) ) {
			return $data;
		}

		$data['result_link'] = $new_url;

		// url_to_cdn_url processed by browsercache internally.
		$data['browsercache_processed'] = '*';

		return $data;
	}

	/**
	 * Get admin bar menu items.
	 *
	 * @param array $menu_items Menu items.
	 */
	public function w3tc_admin_bar_menu( $menu_items ) {
		$cdn_engine = $this->_config->get_string( 'cdn.engine' );

		if ( Cdn_Util::can_purge_all( $cdn_engine ) ) {
			$menu_items['20710.cdn'] = array(
				'id'     => 'w3tc_cdn_flush_all',
				'parent' => 'w3tc_flush',
				'title'  => __( 'CDN: All', 'w3-total-cache' ),
				'href'   => wp_nonce_url( admin_url( 'admin.php?page=w3tc_cdn&amp;w3tc_flush_cdn' ), 'w3tc' ),
			);
		}

		if ( Cdn_Util::can_purge( $cdn_engine ) ) {
			$menu_items['20790.cdn'] = array(
				'id'     => 'w3tc_cdn_flush',
				'parent' => 'w3tc_flush',
				'title'  => __( 'CDN: Manual Purge', 'w3-total-cache' ),
				'href'   => wp_nonce_url( admin_url( 'admin.php?page=w3tc_cdn&amp;w3tc_cdn_purge' ), 'w3tc' ),
				'meta'   => array( 'onclick' => 'w3tc_popupadmin_bar(this.href); return false' ),
			);
		}

		return $menu_items;
	}

	/**
	 * Add CDN mark to footer.
	 *
	 * @param array $strings Footer strings.
	 */
	public function w3tc_footer_comment( $strings ) {
		$common = Dispatcher::component( 'Cdn_Core' );
		$cdn    = $common->get_cdn();
		$via    = $cdn->get_via();

		$strings[] = sprintf(
			// translators: 1 CDN engine name, 2 rejection reason.
			__(
				'Content Delivery Network via %1$s%2$s',
				'w3-total-cache'
			),
			( $via ? $via : 'N/A' ),
			( empty( $this->cdn_reject_reason ) ? '' : sprintf( ' (%s)', $this->cdn_reject_reason ) )
		);

		if ( $this->_debug ) {
			$strings[] = '{w3tc_cdn_debug_info}';
		}

		return $strings;
	}

	/**
	 * Add after footer CDN mark.
	 *
	 * @param string $buffer Buffer.
	 * @param array  $replaced_urls Replaced URLs.
	 */
	public function w3tc_footer_comment_after( $buffer, $replaced_urls ) {
		$strings = array();

		if ( is_array( $replaced_urls ) && count( $replaced_urls ) ) {
			$strings[] = __( 'Replaced URLs for CDN:', 'w3-total-cache' );

			foreach ( $replaced_urls as $old_url => $new_url ) {
				$strings[] = sprintf(
					'%1$s => %2$s',
					Util_Content::escape_comment( $old_url ),
					Util_Content::escape_comment( $new_url )
				);
			}

			$strings[] = '';
		}

		$buffer = str_replace( '{w3tc_cdn_debug_info}', implode( "\n", $strings ), $buffer );

		return $buffer;
	}
}

/**
 * Class: _Cdn_Plugin_ContentFilter
 *
 * phpcs:disable PSR2.Classes.PropertyDeclaration.Underscore
 * phpcs:disable PSR2.Methods.MethodDeclaration.Underscore
 */
class _Cdn_Plugin_ContentFilter { // phpcs:ignore Generic.Classes.OpeningBraceSameLine.ContentAfterBrace, PEAR.NamingConventions.ValidClassName.StartWithCapital, Generic.Files.OneObjectStructurePerFile.MultipleFound
	/**
	 * Regular expressions.
	 *
	 * @var array
	 */
	private $_regexps = array();

	/**
	 * Placeholders.
	 *
	 * @var array
	 */
	private $_placeholders = array();

	/**
	 * Config.
	 *
	 * @var Config
	 */
	private $_config;

	/**
	 * Replaced URLs.
	 *
	 * @var array
	 */
	private $_replaced_urls = array();

	/**
	 * If background uploading already scheduled
	 *
	 * @var boolean
	 */
	private static $_upload_scheduled = false;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Replace all links.
	 *
	 * @param string $buffer Buffer.
	 *
	 * @return string
	 */
	public function replace_all_links( $buffer ) {
		$this->fill_regexps();

		$srcset_pattern = '~srcset\s*=\s*[\"\'](.*?)[\"\']~';
		$buffer         = preg_replace_callback(
			$srcset_pattern,
			array( $this, '_srcset_replace_callback' ),
			$buffer
		);

		foreach ( $this->_regexps as $regexp ) {
			$buffer = preg_replace_callback(
				$regexp,
				array( $this, '_link_replace_callback' ),
				$buffer
			);
		}

		if ( $this->_config->get_boolean( 'cdn.minify.enable' ) ) {
			if ( $this->_config->get_boolean( 'minify.auto' ) ) {
				$minify_url_regexp = $this->minify_url_regexp( '/[a-zA-Z0-9-_]+\.(css|js)' );

				if ( Cdn_Util::is_engine_mirror( $this->_config->get_string( 'cdn.engine' ) ) ) {
					$processor = array( $this, '_link_replace_callback' );
				} else {
					$processor = array( $this, '_minify_auto_pushcdn_link_replace_callback' );
				}
			} else {
				$minify_url_regexp = $this->minify_url_regexp( '/[a-z0-9]+\..+\.include(-(footer|body))?(-nb)?\.[a-f0-9]+\.(css|js)' );
				$processor         = array( $this, '_link_replace_callback' );
			}

			if ( ! empty( $minify_url_regexp ) ) {
				$regexp = '~(["\'(=])\s*' . $minify_url_regexp . '~U';
				$buffer = preg_replace_callback( $regexp, $processor, $buffer );
			}
		}

		$buffer = $this->replace_placeholders( $buffer );

		return $buffer;
	}

	/**
	 * Link replace callback.
	 *
	 * @param array $matches Matches.
	 *
	 * @return string
	 */
	public function _link_replace_callback( $matches ) {
		list( $match, $quote, $url, , , , $path ) = $matches;

		$path = ltrim( $path, '/' );
		$r    = $this->_link_replace_callback_checks( $match, $quote, $url, $path );
		if ( is_null( $r ) ) {
			$r = $this->_link_replace_callback_ask_cdn( $match, $quote, $url, $path );
		}

		return $r;
	}

	/**
	 * Srcset replace callback.
	 *
	 * @param array $matches Matches.
	 *
	 * @return string
	 */
	public function _srcset_replace_callback( $matches ) {
		list( $match, $srcset ) = $matches;

		if ( empty( $this->_regexps ) ) {
			return $match;
		}

		$index = '%srcset-' . count( $this->_placeholders ) . '%';

		$srcset_urls     = explode( ',', $srcset );
		$new_srcset_urls = array();

		foreach ( $srcset_urls as $set ) {
			preg_match( '~(?P<spaces>^\s*)(?P<url>\S+)(?P<rest>.*)~', $set, $parts );
			if ( isset( $parts['url'] ) ) {
				foreach ( $this->_regexps as $regexp ) {
					$new_url = preg_replace_callback(
						$regexp,
						array(
							$this,
							'_link_replace_callback',
						),
						'"' . $parts['url'] . '">'
					);

					if ( '"' . $parts['url'] . '">' !== $new_url ) {
						$parts['url'] = substr( $new_url, 1, -2 );
						break;
					}
				}
				$new_srcset_urls[] = $parts['spaces'] . $parts['url'] . $parts['rest'];
			} else {
				$new_srcset_urls[] = $set;
			}
		}

		$this->_placeholders[ $index ] = implode( ',', $new_srcset_urls );

		return 'srcset="' . $index . '"';
	}

	/**
	 * Replace placeholders.
	 *
	 * @param string $buffer Buffer.
	 *
	 * @return string
	 */
	private function replace_placeholders( $buffer ) {
		foreach ( $this->_placeholders as $srcset_id => $srcset_content ) {
			$buffer = str_replace( $srcset_id, $srcset_content, $buffer );
		}
		return $buffer;
	}

	/**
	 * Gets regexp for minified files
	 *
	 * @param string $filename_mask Filename mask.
	 *
	 * @return string
	 */
	private function minify_url_regexp( $filename_mask ) {
		$minify_base_url = Util_Environment::filename_to_url(
			Util_Environment::cache_blog_minify_dir()
		);
		$matches         = null;
		if ( ! preg_match( '~((https?://)?([^/]+))(.+)~i', $minify_base_url, $matches ) ) {
			error_log( // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				__(
					'Cant find minification base url, make sure minification folder sits inside WP_CONTENT_DIR and DOCUMENT_ROOT is set correctly',
					'w3-total-cache'
				)
			);
			return '';
		}

		$protocol_domain_regexp = Util_Environment::get_url_regexp( $matches[1] );
		$path_regexp            = Util_Environment::preg_quote( $matches[4] );

		$regexp =
			'(' .
			'(' . $protocol_domain_regexp . ')?' .
			'(' . $path_regexp . $filename_mask . ')' .
			')';
		return $regexp;
	}

	/**
	 * Uploads regex.
	 *
	 * @param unknown $domain_url_regexp Domain URL regular expression.
	 * @param unknown $baseurl Base URL.
	 * @param unknown $upload_info Upload info.
	 * @param unknown $regexps Regular expressions.
	 *
	 * @return array
	 */
	private function make_uploads_regexes( $domain_url_regexp, $baseurl, $upload_info, $regexps ) {
		if ( preg_match( '~' . $domain_url_regexp . '~i', $baseurl ) ) {
			$regexps[] = '~(["\'(=])\s*((' . $domain_url_regexp . ')?('
				. Util_Environment::preg_quote( $upload_info['baseurlpath'] )
				. '([^"\')>]+)))~i';
		} else {
			$parsed                   = @wp_parse_url( $baseurl ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$upload_url_domain_regexp = isset( $parsed['host'] ) ?
				Util_Environment::get_url_regexp( $parsed['scheme'] . '://' . $parsed['host'] ) :
				$domain_url_regexp;
			$baseurlpath              = isset( $parsed['path'] ) ? rtrim( $parsed['path'], '/' ) : '';
			if ( $baseurlpath ) {
				$regexps[] = '~(["\'])\s*((' . $upload_url_domain_regexp . ')?('
					. Util_Environment::preg_quote( $baseurlpath )
					. '([^"\'>]+)))~i';
			} else {
				$regexps[] = '~(["\'])\s*((' . $upload_url_domain_regexp
					. ')(([^"\'>]+)))~i';
			}
		}
		return $regexps;
	}

	/**
	 * Fill regular expressions.
	 */
	private function fill_regexps() {
		$regexps = array();

		$site_path         = Util_Environment::site_url_uri();
		$domain_url_regexp = Util_Environment::home_domain_root_url_regexp();

		$site_domain_url_regexp = false;
		if ( Util_Environment::get_url_regexp( Util_Environment::url_to_host( site_url() ) ) !== $domain_url_regexp ) {
			$site_domain_url_regexp = Util_Environment::get_url_regexp( Util_Environment::url_to_host( site_url() ) );
		}

		if ( $this->_config->get_boolean( 'cdn.uploads.enable' ) ) {
			$upload_info = Util_Http::upload_info();

			if ( $upload_info ) {
				$baseurl = $upload_info['baseurl'];

				if ( defined( 'DOMAIN_MAPPING' ) && DOMAIN_MAPPING ) {
					$parsed  = @wp_parse_url( $upload_info['baseurl'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					$baseurl = home_url() . $parsed['path'];
				}

				$regexps = $this->make_uploads_regexes(
					$domain_url_regexp,
					$baseurl,
					$upload_info,
					$regexps
				);

				if ( $site_domain_url_regexp ) {
					$regexps = $this->make_uploads_regexes(
						$site_domain_url_regexp,
						$baseurl,
						$upload_info,
						$regexps
					);
				}
			}
		}

		if ( $this->_config->get_boolean( 'cdn.includes.enable' ) ) {
			$mask = $this->_config->get_string( 'cdn.includes.files' );
			if ( '' !== $mask ) {
				$regexps[] = '~(["\'(=])\s*((' . $domain_url_regexp . ')?(' .
					Util_Environment::preg_quote( $site_path . WPINC ) .
					'/(' . Cdn_Util::get_regexp_by_mask( $mask ) . ')([^"\'() >]*)))~i';
				if ( $site_domain_url_regexp ) {
					$regexps[] = '~(["\'(=])\s*((' . $site_domain_url_regexp . ')?(' .
						Util_Environment::preg_quote( $site_path . WPINC ) .
						'/(' . Cdn_Util::get_regexp_by_mask( $mask ) .
						')([^"\'() >]*)))~i';
				}
			}
		}

		if ( $this->_config->get_boolean( 'cdn.theme.enable' ) ) {
			$theme_dir = preg_replace( '~' . $domain_url_regexp . '~i', '', get_theme_root_uri() );

			$mask = $this->_config->get_string( 'cdn.theme.files' );

			if ( '' !== $mask ) {
				$regexps[] = '~(["\'(=])\s*((' . $domain_url_regexp . ')?(' .
					Util_Environment::preg_quote( $theme_dir ) . '/(' .
					Cdn_Util::get_regexp_by_mask( $mask ) . ')([^"\'() >]*)))~i';
				if ( $site_domain_url_regexp ) {
					$theme_dir2 = preg_replace( '~' . $site_domain_url_regexp . '~i', '', get_theme_root_uri() );
					$regexps[]  = '~(["\'(=])\s*((' . $site_domain_url_regexp . ')?(' .
						Util_Environment::preg_quote( $theme_dir ) . '/(' .
						Cdn_Util::get_regexp_by_mask( $mask ) .
						')([^"\'() >]*)))~i';
					$regexps[]  = '~(["\'(=])\s*((' . $site_domain_url_regexp . ')?(' .
						Util_Environment::preg_quote( $theme_dir2 ) .
						'/(' . Cdn_Util::get_regexp_by_mask( $mask ) .
						')([^"\'() >]*)))~i';
				}
			}
		}

		if ( $this->_config->get_boolean( 'cdn.custom.enable' ) ) {
			$masks = $this->_config->get_array( 'cdn.custom.files' );
			$masks = array_map( array( '\W3TC\Cdn_Util', 'replace_folder_placeholders_to_uri' ), $masks );
			$masks = array_map( array( '\W3TC\Util_Environment', 'parse_path' ), $masks );

			if ( count( $masks ) ) {
				$custom_regexps_urls            = array();
				$custom_regexps_uris            = array();
				$custom_regexps_docroot_related = array();

				foreach ( $masks as $mask ) {
					if ( ! empty( $mask ) ) {
						if ( Util_Environment::is_url( $mask ) ) {
							$url_match = array();
							if ( preg_match( '~^((https?:)?//([^/]*))(.*)~', $mask, $url_match ) ) {
								$custom_regexps_urls[] = array(
									'domain_url' => Util_Environment::get_url_regexp( $url_match[1] ),
									'uri'        => Cdn_Util::get_regexp_by_mask( $url_match[4] ),
								);
							}
						} elseif ( '/' === substr( $mask, 0, 1 ) ) { // uri.
							$custom_regexps_uris[] = Cdn_Util::get_regexp_by_mask( $mask );
						} else {
							$file = Util_Environment::normalize_path( $mask );   // \ -> backspaces.
							$file = str_replace( Util_Environment::site_root(), '', $file );
							$file = ltrim( $file, '/' );

							$custom_regexps_docroot_related[] = Cdn_Util::get_regexp_by_mask( $mask );
						}
					}
				}

				if ( count( $custom_regexps_urls ) > 0 ) {
					foreach ( $custom_regexps_urls as $regexp ) {
						$regexps[] = '~(["\'(=])\s*((' . $regexp['domain_url'] .
						')?((' . $regexp['uri'] . ')([^"\'() >]*)))~i';
					}
				}
				if ( count( $custom_regexps_uris ) > 0 ) {
					$regexps[] = '~(["\'(=])\s*((' . $domain_url_regexp .
						')?((' . implode( '|', $custom_regexps_uris ) . ')([^"\'() >]*)))~i';
				}

				if ( count( $custom_regexps_docroot_related ) > 0 ) {
					$regexps[] = '~(["\'(=])\s*((' . $domain_url_regexp . ')?(' .
						Util_Environment::preg_quote( $site_path ) .
						'(' . implode( '|', $custom_regexps_docroot_related ) . ')([^"\'() >]*)))~i';
					if ( $site_domain_url_regexp ) {
						$regexps[] = '~(["\'(=])\s*((' . $site_domain_url_regexp . ')?(' .
							Util_Environment::preg_quote( $site_path ) . '(' .
							implode( '|', $custom_regexps_docroot_related ) . ')([^"\'() >]*)))~i';
					}
				}
			}
		}

		$this->_regexps = $regexps;
	}

	/**
	 * Link replace callback, basic checks step.
	 *
	 * @param string $match Match.
	 * @param string $quote Quote.
	 * @param string $url URL.
	 * @param string $path Path.
	 *
	 * @return null|string
	 */
	public function _link_replace_callback_checks( $match, $quote, $url, $path ) {
		global $wpdb;

		static $queue = null, $reject_files = null;

		/**
		 * Check if URL was already replaced
		 */
		if ( isset( $this->_replaced_urls[ $url ] ) ) {
			return $quote . $this->_replaced_urls[ $url ];
		}

		/**
		 * Check URL for rejected files
		 */
		if ( null === $reject_files ) {
			$reject_files = $this->_config->get_array( 'cdn.reject.files' );
		}

		foreach ( $reject_files as $reject_file ) {
			if ( '' !== $reject_file ) {
				$reject_file = Cdn_Util::replace_folder_placeholders( $reject_file );
				$reject_file = Util_Environment::normalize_file( $reject_file );

				$reject_file_regexp = '~^(' . Cdn_Util::get_regexp_by_mask( $reject_file ) . ')~i';

				if ( preg_match( $reject_file_regexp, $path ) ) {
					return $match;
				}
			}
		}

		// Don't replace URL for files that are in the CDN queue.
		if ( null === $queue ) {
			if ( ! Cdn_Util::is_engine_mirror( $this->_config->get_string( 'cdn.engine' ) ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$queue = $wpdb->get_var(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnquotedComplexPlaceholder
						'SELECT `remote_path` FROM `%1$s` WHERE `remote_path` = \'%2$s\'',
						$wpdb->base_prefix . W3TC_CDN_TABLE_QUEUE,
						$path
					)
				);
			} else {
				$queue = false;
			}
		}

		if ( $queue ) {
			return $match;
		}

		return null;
	}

	/**
	 * Link replace callback, url replacement using cdn engine
	 *
	 * @param string $match Matc.
	 * @param string $quote Quote.
	 * @param string $url URL.
	 * @param string $path Path.
	 *
	 * @return null|string
	 */
	public function _link_replace_callback_ask_cdn( $match, $quote, $url, $path ) {
		$common  = Dispatcher::component( 'Cdn_Core' );
		$new_url = $common->url_to_cdn_url( $url, $path );
		if ( ! is_null( $new_url ) ) {
			$this->_replaced_urls[ $url ] = $new_url;
			return $quote . $new_url;
		}

		return $match;
	}

	/**
	 * Link replace callback for urls from minify module using auto mode and in cdn of push type.
	 *
	 * @param array $matches Matches.
	 *
	 * @return string
	 */
	public function _minify_auto_pushcdn_link_replace_callback( $matches ) {
		static $dispatcher = null;

		list( $match, $quote, $url, , , , $path ) = $matches;

		$path = ltrim( $path, '/' );
		$r    = $this->_link_replace_callback_checks( $match, $quote, $url, $path );

		// Check if we can replace that URL (for auto mode it should be uploaded).
		if ( ! Dispatcher::is_url_cdn_uploaded( $url ) ) {
			Dispatcher::component( 'Cdn_Core' )->queue_upload_url( $url );
			if ( ! self::$_upload_scheduled ) {
				wp_schedule_single_event( time(), 'w3_cdn_cron_queue_process' );
				add_action( 'shutdown', 'wp_cron' );

				self::$_upload_scheduled = true;
			}

			return $match;
		}

		if ( is_null( $r ) ) {
			$r = $this->_link_replace_callback_ask_cdn( $match, $quote, $url, $path );
		}
		return $r;
	}

	/**
	 * Get replaced URLs.
	 *
	 * @return array
	 */
	public function get_replaced_urls() {
		return $this->_replaced_urls;
	}
}
