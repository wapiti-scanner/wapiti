<?php

namespace WPForms\Admin\Addons;

/**
 * Addons data handler.
 *
 * @since 1.6.6
 */
class Addons {

	/**
	 * Addons cache object.
	 *
	 * @since 1.6.6
	 *
	 * @var \WPForms\Admin\Addons\AddonsCache
	 */
	private $cache;

	/**
	 * All Addons data.
	 *
	 * @since 1.6.6
	 *
	 * @var array
	 */
	private $addons;

	/**
	 * Available addons data.
	 *
	 * @since 1.6.6
	 *
	 * @var array
	 */
	private $available_addons;

	/**
	 * Determine if the class is allowed to load.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function allow_load() {

		$has_permissions  = wpforms_current_user_can( [ 'create_forms', 'edit_forms' ] );
		$allowed_requests = wpforms_is_admin_ajax() || wpforms_is_admin_page() || wpforms_is_admin_page( 'builder' );

		return $has_permissions && $allowed_requests;
	}

	/**
	 * Initialize class.
	 *
	 * @since 1.6.6
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->cache  = wpforms()->get( 'addons_cache' );
		$this->addons = $this->cache->get_cached();

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.6
	 */
	protected function hooks() {

		add_action( 'admin_init', [ $this, 'get_available' ] );

		do_action( 'wpforms_admin_addons_init' );
	}

	/**
	 * Get all addons data as array.
	 *
	 * @since 1.6.6
	 *
	 * @param bool $force_cache_update Determine if we need to update cache. Default is `false`.
	 *
	 * @return array
	 */
	public function get_all( $force_cache_update = false ) {

		return (bool) $force_cache_update ? $this->cache->update_cache() : $this->addons;
	}

	/**
	 * Get filtered addons data.
	 *
	 * Usage:
	 *      ->get_filtered( $this->addons, [ 'category' => 'payments' ] )    - addons for the payments panel.
	 *      ->get_filtered( $this->addons, [ 'license' => 'elite' ] )        - addons available for 'elite' license.
	 *
	 * @since 1.6.6
	 *
	 * @param array $addons Raw addons data.
	 * @param array $args   Arguments array.
	 *
	 * @return array Addons data filtered according to given arguments.
	 */
	private function get_filtered( $addons, $args ) {

		if ( empty( $addons ) ) {
			return [];
		}

		$default_args = [
			'category' => '',
			'license'  => '',
		];

		$args = wp_parse_args( $args, $default_args );

		$filtered_addons = [];

		foreach ( $addons as $addon ) {
			foreach ( [ 'category', 'license' ] as $arg_key ) {
				if (
					! empty( $args[ $arg_key ] ) &&
					! empty( $addon[ $arg_key ] ) &&
					is_array( $addon[ $arg_key ] ) &&
					in_array( strtolower( $args[ $arg_key ] ), $addon[ $arg_key ], true )
				) {
					$filtered_addons[] = $addon;
				}
			}
		}

		return $filtered_addons;
	}

	/**
	 * Get available addons data by category.
	 *
	 * @since 1.6.6
	 *
	 * @param string $category Addon category.
	 *
	 * @return array.
	 */
	public function get_by_category( $category ) {

		return $this->get_filtered( $this->available_addons, [ 'category' => $category ] );
	}

	/**
	 * Get available addons data by license.
	 *
	 * @since 1.6.6
	 *
	 * @param string $license Addon license.
	 *
	 * @return array.
	 */
	public function get_by_license( $license ) {

		return $this->get_filtered( $this->available_addons, [ 'license' => $license ] );
	}

	/**
	 * Get available addons data by slugs.
	 *
	 * @since 1.6.8
	 *
	 * @param array $slugs Addon slugs.
	 *
	 * @return array
	 */
	public function get_by_slugs( $slugs ) {

		if ( empty( $slugs ) || ! is_array( $slugs ) ) {
			return [];
		}

		$result_addons = [];

		foreach ( $slugs as $slug ) {
			$addon = $this->get_addon( $slug );

			if ( ! empty( $addon ) ) {
				$result_addons[] = $addon;
			}
		}

		return $result_addons;
	}

	/**
	 * Get available addon data by slug.
	 *
	 * @since 1.6.6
	 *
	 * @param string $slug Addon slug, can be both "wpforms-drip" and "drip".
	 *
	 * @return array Single addon data. Empty array if addon is not found.
	 */
	public function get_addon( $slug ) {

		$slug = 'wpforms-' . str_replace( 'wpforms-', '', sanitize_key( $slug ) );

		$addon = ! empty( $this->available_addons[ $slug ] ) ? $this->available_addons[ $slug ] : [];

		// In case if addon is "not available" let's try to get and prepare addon data from all addons.
		if ( empty( $addon ) ) {
			$addon = ! empty( $this->addons[ $slug ] ) ? $this->prepare_addon_data( $this->addons[ $slug ] ) : [];
		}

		return $addon;
	}

	/**
	 * Get license level of the addon.
	 *
	 * @since 1.6.6
	 *
	 * @param array|string $addon Addon data array OR addon slug.
	 *
	 * @return string License level: pro | elite.
	 */
	private function get_license_level( $addon ) {

		if ( empty( $addon ) ) {
			return '';
		}

		$addon            = is_string( $addon ) ? $this->get_addon( $addon ) : $addon;
		$addon['license'] = empty( $addon['license'] ) ? [] : (array) $addon['license'];

		// TODO: convert to a class constant when we will drop PHP 5.5.
		$levels  = [ 'basic', 'plus', 'pro', 'elite', 'agency', 'ultimate' ];
		$license = '';

		foreach ( $levels as $level ) {
			if ( in_array( $level, $addon['license'], true ) ) {
				$license = $level;

				break;
			}
		}

		if ( empty( $license ) ) {
			return '';
		}

		return in_array( $license, [ 'basic', 'plus', 'pro' ], true ) ? 'pro' : 'elite';
	}

	/**
	 * Determine if user's license level has access.
	 *
	 * @since 1.6.6
	 *
	 * @param array|string $addon Addon data array OR addon slug.
	 *
	 * @return bool
	 */
	protected function has_access( $addon ) {

		return false;
	}

	/**
	 * Return array of addons available to display. All data prepared and normalized.
	 * "Available to display" means that addon need to be displayed as education item (addon is not installed or not activated).
	 *
	 * @since 1.6.6
	 *
	 * @return array
	 */
	public function get_available() {

		if ( empty( $this->addons ) || ! is_array( $this->addons ) ) {
			return [];
		}

		if ( empty( $this->available_addons ) ) {
			$this->available_addons = array_map( [ $this, 'prepare_addon_data' ], $this->addons );
			$this->available_addons = array_filter(
				$this->available_addons,
				static function( $addon ) {

					return isset( $addon['status'], $addon['plugin_allow'] ) && ( $addon['status'] !== 'active' || ! $addon['plugin_allow'] );
				}
			);
		}

		return $this->available_addons;
	}

	/**
	 * Prepare addon data.
	 *
	 * @since 1.6.6
	 *
	 * @param array $addon Addon data.
	 *
	 * @return array Extended addon data.
	 */
	protected function prepare_addon_data( $addon ) {

		if ( empty( $addon ) ) {
			return [];
		}

		$addon['title'] = ! empty( $addon['title'] ) ? $addon['title'] : '';
		$addon['slug']  = ! empty( $addon['slug'] ) ? $addon['slug'] : '';

		// We need the cleared name of the addon, without the ' addon' suffix, for further use.
		$addon['name'] = preg_replace( '/ addon$/i', '', $addon['title'] );

		/* translators: %s - addon name. */
		$addon['modal_name']    = sprintf( esc_html__( '%s addon', 'wpforms-lite' ), $addon['name'] );
		$addon['clear_slug']    = str_replace( 'wpforms-', '', $addon['slug'] );
		$addon['utm_content']   = ucwords( str_replace( '-', ' ', $addon['clear_slug'] ) );
		$addon['license']       = empty( $addon['license'] ) ? [] : (array) $addon['license'];
		$addon['license_level'] = $this->get_license_level( $addon );
		$addon['icon']          = ! empty( $addon['icon'] ) ? $addon['icon'] : '';
		$addon['path']          = sprintf( '%1$s/%1$s.php', $addon['slug'] );
		$addon['video']         = ! empty( $addon['video'] ) ? $addon['video'] : '';
		$addon['plugin_allow']  = $this->has_access( $addon );
		$addon['status']        = 'missing';
		$addon['action']        = 'upgrade';
		$addon['page_url']      = empty( $addon['url'] ) ? '' : $addon['url'];
		$addon['doc_url']       = empty( $addon['doc'] ) ? '' : $addon['doc'];
		$addon['url']           = '';

		static $nonce   = '';
		$nonce          = empty( $nonce ) ? wp_create_nonce( 'wpforms-admin' ) : $nonce;
		$addon['nonce'] = $nonce;

		return $addon;
	}
}
