<?php
/**
 * Settings class.
 *
 * @package automattic/jetpack-publicize
 */

namespace Automattic\Jetpack\Publicize\Social_Image_Generator;

use Automattic\Jetpack\Modules;

/**
 * This class is used to get and update SIG-specific global settings.
 */
class Settings {
	/**
	 * Name of the database option.
	 *
	 * @var string
	 */
	const OPTION_NAME = 'jetpack_social_image_generator_settings';

	/**
	 * Array with SIG's settings.
	 *
	 * @var array $settings
	 */
	public $settings;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->settings = $this->get_settings();
	}

	/**
	 * Get all current SIG settings.
	 *
	 * @return array
	 */
	private function get_settings() {
		$settings = get_option( self::OPTION_NAME );

		if ( empty( $settings ) || ! is_array( $settings ) ) {
			return array();
		}

		return $settings;
	}

	/**
	 * Update a SIG setting.
	 *
	 * @param string $key The key to update.
	 * @param mixed  $value The value to set for the key.
	 * @return bool True if the value was updated, false otherwise.
	 */
	private function update_setting( $key, $value ) {
		$settings       = array_replace_recursive( $this->get_settings(), array( $key => $value ) );
		$this->settings = $settings;

		return update_option( self::OPTION_NAME, $settings );
	}

	/**
	 * Check if SIG is available.
	 *
	 * @return bool True if SIG is available, false otherwise.
	 */
	public function is_available() {
		global $publicize;

		if ( ! $publicize ) {
			return false;
		}

		return $publicize->has_social_image_generator_feature();
	}

	/**
	 * Check if SIG is enabled.
	 *
	 * @return bool True if SIG is enabled, false otherwise.
	 */
	public function is_enabled() {
		// If the feature isn't available it should never be enabled.
		if ( ! $this->is_available() ) {
			return false;
		}

		// SIG cannot be enabled without Publicize.
		if ( ! ( new Modules() )->is_active( 'publicize' ) ) {
			return false;
		}

		if ( isset( $this->settings['enabled'] ) ) {
			return $this->settings['enabled'];
		}

		return false;
	}

	/**
	 * Enable or disable SIG.
	 *
	 * @param bool $value True to enable SIG, false to disable.
	 * @return bool True if the setting was updated successfully, false otherwise.
	 */
	public function set_enabled( $value ) {
		return $this->update_setting( 'enabled', (bool) $value );
	}

	/**
	 * Get an array of all current defaults.
	 *
	 * @return array
	 */
	public function get_defaults() {
		if ( isset( $this->settings['defaults'] ) ) {
			return $this->settings['defaults'];
		}

		return array(
			'template' => Templates::DEFAULT_TEMPLATE,
		);
	}

	/**
	 * Get the current default template.
	 *
	 * @return string
	 */
	public function get_default_template() {
		$defaults = $this->get_defaults();

		return isset( $defaults['template'] ) ? $defaults['template'] : Templates::DEFAULT_TEMPLATE;
	}

	/**
	 * Set a new default template.
	 *
	 * @param string $template Name of the template.
	 * @return bool True if the setting was updated successfully, false otherwise.
	 */
	public function set_default_template( $template ) {
		return self::update_setting( 'defaults', array_merge( $this->get_defaults(), array( 'template' => $template ) ) );
	}
}
