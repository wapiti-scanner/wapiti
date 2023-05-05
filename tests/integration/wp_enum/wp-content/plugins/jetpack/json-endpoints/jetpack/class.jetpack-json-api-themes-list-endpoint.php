<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Theme list endpoint class.
 *
 * GET /sites/%s/themes
 */
class Jetpack_JSON_API_Themes_List_Endpoint extends Jetpack_JSON_API_Themes_Endpoint {
	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'switch_themes';

	/**
	 * Validate the input.
	 *
	 * @param string $theme - the theme we're validating (unused, for keeping in sync with parent class).
	 *
	 * @return bool
	 */
	public function validate_input( $theme ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$this->themes = wp_get_themes( array( 'allowed' => true ) );
		return true;
	}

}
