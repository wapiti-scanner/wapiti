<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Base class for working with Jetpack Modules.
 */
abstract class Jetpack_JSON_API_Modules_Endpoint extends Jetpack_JSON_API_Endpoint {

	/**
	 * The modules.
	 *
	 * @var array
	 */
	protected $modules = array();

	/**
	 * If we're working in bulk.
	 *
	 * @var boolean
	 */
	protected $bulk = true;

	/**
	 * Response format.
	 *
	 * @var array
	 */
	public static $_response_format = array( // phpcs:ignore PSR2.Classes.PropertyDeclaration.Underscore
		'id'          => '(string)   The module\'s ID',
		'active'      => '(boolean)  The module\'s status.',
		'name'        => '(string)   The module\'s name.',
		'description' => '(safehtml) The module\'s description.',
		'sort'        => '(int)      The module\'s display order.',
		'introduced'  => '(string)   The Jetpack version when the module was introduced.',
		'changed'     => '(string)   The Jetpack version when the module was changed.',
		'free'        => '(boolean)  The module\'s Free or Paid status.',
		'module_tags' => '(array)    The module\'s tags.',
		'override'    => '(string)   The module\'s override. Empty if no override, otherwise \'active\' or \'inactive\'',
	);

	/**
	 * The result.
	 *
	 * @return array
	 */
	protected function result() {

		$modules = $this->get_modules();

		if ( ! $this->bulk && ! empty( $modules ) ) {
			return array_pop( $modules );
		}

		return array( 'modules' => $modules );
	}

	/**
	 * Walks through either the submitted modules or list of themes and creates the global array.
	 *
	 * @param string $module - the modules.
	 *
	 * @return bool|WP_Error
	 */
	protected function validate_input( $module ) {
		$args = $this->input();
		// lets set what modules were requested, and validate them
		if ( ! isset( $module ) || empty( $module ) ) {

			if ( ! $args['modules'] || empty( $args['modules'] ) ) {
				return new WP_Error( 'missing_module', __( 'You are required to specify a module.', 'jetpack' ), 400 );
			}
			if ( is_array( $args['modules'] ) ) {
				$this->modules = $args['modules'];
			} else {
				$this->modules[] = $args['modules'];
			}
		} else {
			$this->modules[] = urldecode( $module );
			$this->bulk      = false;
		}

		$error = $this->validate_modules();
		if ( is_wp_error( $error ) ) {
			return $error;
		}

		return parent::validate_input( $module );
	}

	/**
	 * Walks through submitted themes to make sure they are valid
	 *
	 * @return bool|WP_Error
	 */
	protected function validate_modules() {
		foreach ( $this->modules as $module ) {
			if ( ! Jetpack::is_module( $module ) ) {
				// Translators: the module that's not found.
				return new WP_Error( 'unknown_jetpack_module', sprintf( __( 'Module not found: `%s`.', 'jetpack' ), $module ), 404 );
			}
		}
		return true;
	}

	/**
	 * Format the module.
	 *
	 * @param string $module_slug - the module slug.
	 *
	 * @return array
	 */
	protected static function format_module( $module_slug ) {
		$module_data = Jetpack::get_module( $module_slug );

		$module                      = array();
		$module['id']                = $module_slug;
		$module['active']            = Jetpack::is_module_active( $module_slug );
		$module['name']              = $module_data['name'];
		$module['short_description'] = $module_data['description'];
		$module['sort']              = $module_data['sort'];
		$module['introduced']        = $module_data['introduced'];
		$module['changed']           = $module_data['changed'];
		$module['free']              = $module_data['free'];
		$module['module_tags']       = array_map( 'jetpack_get_module_i18n_tag', $module_data['module_tags'] );

		$overrides_instance = Jetpack_Modules_Overrides::instance();
		$module['override'] = $overrides_instance->get_module_override( $module_slug );

		// Fetch the HTML formatted long description
		ob_start();
		/** This action is documented in class.jetpack-modules-list-table.php */
		do_action( 'jetpack_module_more_info_' . $module_slug );
		$module['description'] = ob_get_clean();

		return $module;
	}

	/**
	 * Format a list of modules for public display, using the supplied offset and limit args
	 *
	 * @uses   WPCOM_JSON_API_Endpoint::query_args()
	 * @return array         Public API modules objects
	 */
	protected function get_modules() {
		$modules = array_values( $this->modules );
		// do offset & limit - we've already returned a 400 error if they're bad numbers
		$args = $this->query_args();

		if ( isset( $args['offset'] ) ) {
			$modules = array_slice( $modules, (int) $args['offset'] );
		}
		if ( isset( $args['limit'] ) ) {
			$modules = array_slice( $modules, 0, (int) $args['limit'] );
		}

		return array_map( array( $this, 'format_module' ), $modules );
	}

}
