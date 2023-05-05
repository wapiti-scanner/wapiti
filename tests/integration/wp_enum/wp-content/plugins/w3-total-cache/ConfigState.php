<?php
namespace W3TC;

/**
 * Provides state information - state can be changed by plugin during lifetime,
 * while configuration is static
 *
 * master keys:
 *   common.install - time() of plugin installation
 *   common.support_us_invitations - number of invitations to support us shown
 *   common.next_support_us_invitation - time() of next support us invitation
 *   common.hide_note_wp_content_permissions
 *   common.hide_note_no_zlib
 *   common.hide_note_zlib_output_compression
 *   common.show_note.nginx_restart_required
 *   common.hide_note_php_version_56
 *   license.status
 *   license.next_check - time of next check
 *   license.terms - accepted/declined/''
 *   license.community_terms - accepted/declined/'' (master)
 *   minify.error.file
 *   minify.error.last
 *   minify.error.notification.last
 *   minify.show_note_minify_error
 *   minify.hide_minify_help
 *   extension.cloudflare.next_ips_check
 *   extension.cloudflare.ips.ip4
 *   extension.cloudflare.ips.ip6
 *
 * blog-level keys:
 *   newrelic.hide_note_pageload_slow
 *   minify.show_note.need_flush
 *   minify.show_note.need_flush.timestamp - when the note was set
 *   cdn.hide_note_no_curl
 *   cdn.google_drive.access_token
 *   cdn.rackspace_cf.access_state
 *   cdn.rackspace_cdn.access_state
 *   cdn.stackpath2.access_token
 *   cdn.show_note_theme_changed
 *   cdn.show_note_wp_upgraded
 *   cdn.show_note_cdn_upload
 *   cdn.show_note_cdn_reupload
 *   common.hide_note_no_permalink_rules
 *   common.show_note.plugins_updated
 *   common.show_note.plugins_updated.timestamp - when the note was set
 *   common.show_note.flush_statics_needed
 *   common.show_note.flush_statics_needed.timestamp
 *   common.show_note.flush_posts_needed
 *   common.show_note.flush_posts_needed.timestamp - when the note was set
 *   objectcache.show_note.flush_needed
 *   objectcache.show_note.flush_needed.timestamp - when the note was set
 *   extension.<extension_id>.hide_note_suggest_activation
 *   track.stackpath_signup
 */
class ConfigState {
	private $_data;
	private $_is_master;



	/**
	 * Constructor
	 */
	public function __construct( $is_master ) {
		$this->_is_master = $is_master;

		if ( $is_master )
			$data_raw = get_site_option( 'w3tc_state' );
		else
			$data_raw = get_option( 'w3tc_state' );

		$this->_data = @json_decode( $data_raw, true );
		if ( !is_array( $this->_data ) ) {
			$this->_data = array();
			$this->apply_defaults();
			$this->save();
		}
	}



	/**
	 * Returns value
	 *
	 * @param string  $key
	 * @param string  $default
	 * @return mixed
	 */
	public function get( $key, $default ) {
		if ( !isset( $this->_data[$key] ) )
			return $default;

		return $this->_data[$key];
	}



	/**
	 * Returns string value
	 *
	 * @param string  $key
	 * @param string  $default
	 * @param boolean $trim
	 * @return string
	 */
	public function get_string( $key, $default = '', $trim = true ) {
		$value = (string)$this->get( $key, $default );

		return $trim ? trim( $value ) : $value;
	}



	/**
	 * Returns integer value
	 *
	 * @param string  $key
	 * @param integer $default
	 * @return integer
	 */
	public function get_integer( $key, $default = 0 ) {
		return (integer)$this->get( $key, $default );
	}



	/**
	 * Returns boolean value
	 *
	 * @param string  $key
	 * @param boolean $default
	 * @return boolean
	 */
	public function get_boolean( $key, $default = false ) {
		$v = $this->get( $key, $default );
		if ( $v === 'false' || $v === 0 )
			$v = false;

		return (boolean)$v;
	}



	/**
	 * Returns array value
	 *
	 * @param string  $key
	 * @param array   $default
	 * @return array
	 */
	public function get_array( $key, $default = array() ) {
		return (array)$this->get( $key, $default );
	}



	/**
	 * Sets config value
	 *
	 * @param string  $key
	 * @param string  $value
	 * @return value set
	 */
	public function set( $key, $value ) {
		$this->_data[$key] = $value;
	}



	public function reset() {
		$this->_data = array();
		$this->apply_defaults();
	}



	/**
	 * Saves modified config
	 */
	public function save() {
		if ( $this->_is_master )
			update_site_option( 'w3tc_state', json_encode( $this->_data ) );
		else
			update_option( 'w3tc_state', json_encode( $this->_data ) );
	}



	private function apply_defaults() {
		$this->set( 'common.install', time() );
		$this->set( 'common.install_version', W3TC_VERSION );
	}
}
