<?php
/**
 * Unifies admin color scheme selection across WP.com sites.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

/**
 * Unifies admin color scheme selection across WP.com sites.
 */
class Admin_Color_Schemes {

	/**
	 * Admin_Color_Schemes constructor.
	 */
	public function __construct() {
		add_action( 'admin_init', array( $this, 'register_admin_color_schemes' ) );
		add_action( 'rest_api_init', array( $this, 'register_admin_color_meta' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_core_color_schemes_overrides' ) );
	}

	/**
	 * Makes admin_color available in users REST API endpoint.
	 */
	public function register_admin_color_meta() {
		register_meta(
			'user',
			'admin_color',
			array(
				'auth_callback' => array( $this, 'update_admin_color_permissions_check' ),
				'description'   => __( 'Slug of the admin color scheme.', 'jetpack' ),
				'single'        => true,
				'show_in_rest'  => array(
					'schema' => array( 'default' => 'fresh' ),
				),
				'type'          => 'string',
			)
		);
	}

	/**
	 * Permission callback to edit the `admin_color` user meta.
	 *
	 * @param bool   $allowed   Whether the given user is allowed to edit this meta value.
	 * @param string $meta_key  Meta key. In this case `admin_color`.
	 * @param int    $object_id Queried user ID.
	 * @return bool
	 */
	public function update_admin_color_permissions_check( $allowed, $meta_key, $object_id ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter, VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return current_user_can( 'edit_user', $object_id );
	}

	/**
	 * Get the admin color scheme URL based on the environment
	 *
	 * @param string $color_scheme  The color scheme to get the URL for.
	 * @return string
	 */
	public function get_admin_color_scheme_url( $color_scheme ) {
		return plugins_url( '_inc/build/masterbar/admin-color-schemes/colors/' . $color_scheme . '/colors.css', JETPACK__PLUGIN_FILE );
	}

	/**
	 * Registers new admin color schemes
	 */
	public function register_admin_color_schemes() {

		wp_admin_css_color(
			'aquatic',
			__( 'Aquatic', 'jetpack' ),
			$this->get_admin_color_scheme_url( 'aquatic' ),
			array( '#135e96', '#007e65', '#043959', '#c5d9ed' ),
			array(
				'base'    => '#c5d9ed',
				'focus'   => '#fff',
				'current' => '#01263a',
			)
		);

		wp_admin_css_color(
			'classic-blue',
			__( 'Classic Blue', 'jetpack' ),
			$this->get_admin_color_scheme_url( 'classic-blue' ),
			array( '#135e96', '#b26200', '#dcdcde', '#646970' ),
			array(
				'base'    => '#646970',
				'focus'   => '#2271b1',
				'current' => '#fff',
			)
		);

		wp_admin_css_color(
			'classic-bright',
			__( 'Classic Bright', 'jetpack' ),
			$this->get_admin_color_scheme_url( 'classic-bright' ),
			array( '#135e96', '#c9256e', '#ffffff', '#e9eff5' ),
			array(
				'base'    => '#646970',
				'focus'   => '#1d2327',
				'current' => '#0a4b78',
			)
		);

		wp_admin_css_color(
			'classic-dark',
			__( 'Classic Dark', 'jetpack' ),
			$this->get_admin_color_scheme_url( 'classic-dark' ),
			array( '#101517', '#c9356e', '#32373c', '#0073aa' ),
			array(
				'base'    => '#a2aab2',
				'focus'   => '#00b9eb',
				'current' => '#fff',
			)
		);

		wp_admin_css_color(
			'contrast',
			__( 'Contrast', 'jetpack' ),
			$this->get_admin_color_scheme_url( 'contrast' ),
			array( '#101517', '#ffffff', '#32373c', '#b4b9be' ),
			array(
				'base'    => '#1d2327',
				'focus'   => '#fff',
				'current' => '#fff',
			)
		);

		wp_admin_css_color(
			'nightfall',
			__( 'Nightfall', 'jetpack' ),
			$this->get_admin_color_scheme_url( 'nightfall' ),
			array( '#00131c', '#043959', '#2271b1', '#9ec2e6' ),
			array(
				'base'    => '#9ec2e6',
				'focus'   => '#fff',
				'current' => '#fff',
			)
		);

		wp_admin_css_color(
			'powder-snow',
			__( 'Powder Snow', 'jetpack' ),
			$this->get_admin_color_scheme_url( 'powder-snow' ),
			array( '#101517', '#2271b1', '#dcdcde', '#646970' ),
			array(
				'base'    => '#646970',
				'focus'   => '#135e96',
				'current' => '#fff',
			)
		);

		wp_admin_css_color(
			'sakura',
			__( 'Sakura', 'jetpack' ),
			$this->get_admin_color_scheme_url( 'sakura' ),
			array( '#005042', '#f2ceda', '#2271b1', '#8c1749' ),
			array(
				'base'    => '#8c1749',
				'focus'   => '#4f092a',
				'current' => '#fff',
			)
		);

		wp_admin_css_color(
			'sunset',
			__( 'Sunset', 'jetpack' ),
			$this->get_admin_color_scheme_url( 'sunset' ),
			array( '#691c1c', '#b26200', '#f0c930', '#facfd2' ),
			array(
				'base'    => '#facfd2',
				'focus'   => '#fff',
				'current' => '#4f3500',
			)
		);
	}

	/**
	 * Enqueues current color-scheme overrides for core color schemes
	 */
	public function enqueue_core_color_schemes_overrides() {
		$core_color_schemes = array( 'blue', 'coffee', 'ectoplasm', 'fresh', 'light', 'midnight', 'modern', 'ocean', 'sunrise' );
		$color_scheme       = get_user_option( 'admin_color' );
		if ( in_array( $color_scheme, $core_color_schemes, true ) ) {
			wp_enqueue_style(
				'jetpack-core-color-schemes-overrides',
				$this->get_admin_color_scheme_url( $color_scheme ),
				array(),
				JETPACK__VERSION
			);
		}
	}
}
