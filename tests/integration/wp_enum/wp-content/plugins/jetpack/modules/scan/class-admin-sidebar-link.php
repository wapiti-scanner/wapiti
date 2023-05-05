<?php
/**
 * A class that adds a scan and backup link to the admin sidebar.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Scan;

use Automattic\Jetpack\My_Jetpack\Products\Backup;
use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Status\Host;
use Jetpack_Core_Json_Api_Endpoints;

/**
 * Class Main
 *
 * Responsible for showing the link if available.
 *
 * @package Automattic\Jetpack\Scan
 */
class Admin_Sidebar_Link {

	const SCHEDULE_ACTION_HOOK = 'jetpack_scan_refresh_states_event';

	/**
	 * The singleton instance of this class.
	 *
	 * @var Admin_Sidebar_Link
	 */
	protected static $instance;

	/**
	 * Used to check if we need to schedule the refresh or we need to do it.
	 *
	 * @var boolean | null
	 */
	private $schedule_refresh_checked;

	/**
	 * Get the singleton instance of the class.
	 *
	 * @return Admin_Sidebar_Link
	 */
	public static function instance() {
		if ( ! isset( self::$instance ) ) {
			self::$instance = new Admin_Sidebar_Link();
			self::$instance->init_hooks();
		}

		return self::$instance;
	}

	/**
	 * Adds action hooks.
	 */
	public function init_hooks() {
		add_action( 'jetpack_admin_menu', array( $this, 'maybe_add_admin_link' ), 99 );
		add_action( self::SCHEDULE_ACTION_HOOK, array( $this, 'refresh_state_cache' ) );
	}

	/**
	 * Adds a link to the Scan and Backup page.
	 */
	public function maybe_add_admin_link() {
		if ( ! $this->should_show_link() ) {
			return;
		}

		if ( $this->should_show_scan() ) {
			$menu_label = __( 'Scan', 'jetpack' );
			$url        = Redirect::get_url( 'calypso-scanner' );
			add_submenu_page( 'jetpack', $menu_label, esc_html( $menu_label ) . ' <span class="dashicons dashicons-external"></span>', 'manage_options', esc_url( $url ), null, $this->get_link_offset() );
		}

		if ( $this->should_show_backup() ) {
			$menu_label = __( 'VaultPress', 'jetpack' );
			$url        = Redirect::get_url( 'calypso-backups' );
			add_submenu_page( 'jetpack', $menu_label, esc_html( $menu_label ) . ' <span class="dashicons dashicons-external"></span>', 'manage_options', esc_url( $url ), null, $this->get_link_offset() );
		}
	}

	/**
	 * We create a menu offset by counting all the pages that have a jetpack_admin_page set as the capability.
	 *
	 * This makes it so that the highlight of the pages works as expected. When you click on the Setting or Dashboard.
	 *
	 * @return int Menu offset.
	 */
	private function get_link_offset() {
		global $submenu;
		$offset = 0;

		if ( ! array_key_exists( 'jetpack', $submenu ) ) {
			return $offset;
		}

		foreach ( $submenu['jetpack'] as $link ) {
			if ( 'jetpack_admin_page' !== $link[1] ) {
				break;
			}
			++$offset;
		}

		return $offset;
	}

	/**
	 * Refreshes the state cache via API call. Called via cron.
	 */
	public function refresh_state_cache() {
		Jetpack_Core_Json_Api_Endpoints::get_scan_state();
		Jetpack_Core_Json_Api_Endpoints::get_rewind_data();
	}

	/**
	 * Returns true if the link should appear.
	 *
	 * @return boolean
	 */
	private function should_show_link() {
		// Jetpack Scan/Backup is currently not supported on multisite.
		if ( is_multisite() ) {
			return false;
		}

		// Check if VaultPress is active, the assumption there is that VaultPress is working.
		// It has its link the adminbar.
		if ( class_exists( 'VaultPress' ) ) {
			return false;
		}

		return $this->should_show_scan() || $this->should_show_backup();
	}

	/**
	 * Check if we should display the Scan menu item.
	 *
	 * It will only be displayed if site has Scan enabled, is not an Atomic site, and the stand-alone Protect plugin is not active, because it will have a menu item of its own.
	 *
	 * @return boolean
	 */
	private function should_show_scan() {
		return $this->has_scan() && ! $this->has_protect_plugin() && ! ( new Host() )->is_woa_site();
	}

	/**
	 * Check if we should display the Backup menu item.
	 *
	 * It will only be displayed if site has Backup enabled and the stand-alone Backup plugin is not active, because it will have a menu item of its own.
	 *
	 * @return boolean
	 */
	private function should_show_backup() {
		return $this->has_backup() && ! $this->has_backup_plugin();
	}

	/**
	 * Detects if Scan is enabled.
	 *
	 * @return boolean
	 */
	private function has_scan() {
		$this->maybe_refresh_transient_cache();
		$scan_state = get_transient( 'jetpack_scan_state' );
		if ( ! $scan_state ) {
			return false;
		}

		return isset( $scan_state->state ) && 'unavailable' !== $scan_state->state;
	}

	/**
	 * Detects if Protect plugin is active.
	 *
	 * @return boolean
	 */
	private function has_protect_plugin() {
		return class_exists( 'Jetpack_Protect' );
	}

	/**
	 * Detects if Backup is enabled.
	 *
	 * @return boolean
	 */
	private function has_backup() {
		$this->maybe_refresh_transient_cache();
		$rewind_state = get_transient( 'jetpack_rewind_state' );
		if ( ! $rewind_state ) {
			return false;
		}

		return isset( $rewind_state->state ) && 'unavailable' !== $rewind_state->state;
	}

	/**
	 * Detects if Backup plugin is active.
	 *
	 * @return boolean
	 */
	private function has_backup_plugin() {
		return Backup::is_active();
	}

	/**
	 * Triggers a cron job to refresh the Scan and Rewind state cache.
	 */
	private function maybe_refresh_transient_cache() {
		if ( $this->schedule_refresh_checked ) {
			return;
		}

		// Do we have a jetpack_scan and jetpack_rewind state set?
		if ( get_transient( 'jetpack_scan_state' ) && get_transient( 'jetpack_rewind_state' ) ) {
			return;
		}

		if ( false === wp_next_scheduled( self::SCHEDULE_ACTION_HOOK ) ) {
			wp_schedule_single_event( time(), self::SCHEDULE_ACTION_HOOK );
		}

		$this->schedule_refresh_checked = true;
	}
}
