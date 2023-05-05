<?php
/**
 * File: Base_Page_Settings.php
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: Base_Page_Settings
 *
 * phpcs:disable PSR2.Classes.PropertyDeclaration.Underscore
 */
class Base_Page_Settings {
	/**
	 * Config
	 *
	 * @var Config
	 */
	protected $_config = null;

	/**
	 * Notes
	 *
	 * @var array
	 */
	protected $_notes = array();

	/**
	 * Errors
	 *
	 * @var array
	 */
	protected $_errors = array();

	/**
	 * Used in PHPMailer init function
	 *
	 * @var string
	 */
	protected $_phpmailer_sender = '';

	/**
	 * Master configuration
	 *
	 * @var Config
	 */
	protected $_config_master;

	/**
	 * Page
	 *
	 * @var number
	 */
	protected $_page;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->_config        = Dispatcher::config();
		$this->_config_master = Dispatcher::config_master();
		$this->_page          = Util_Admin::get_current_page();
	}

	/**
	 * Render header.
	 */
	public function options() {
		$this->view();
	}

	/**
	 * Render footer.
	 */
	public function render_footer() {
		include W3TC_INC_OPTIONS_DIR . '/common/footer.php';
	}

	/**
	 * Returns true if config section is sealed.
	 *
	 * @param string $section Config section.
	 *
	 * @return boolean
	 */
	protected function is_sealed( $section ) {
		return true;
	}

	/**
	 * Returns true if we edit master config.
	 *
	 * @return boolean
	 */
	protected function is_master() {
		return $this->_config->is_master();
	}

	/**
	 * Prints checkbox with config option value.
	 *
	 * @param string $option_id    Option ID.
	 * @param bool   $disabled     Disabled flag.
	 * @param string $class_prefix Class prefix.
	 * @param bool   $label        Label.
	 * @param bool   $force_value  Override value.
	 */
	protected function checkbox( $option_id, $disabled = false, $class_prefix = '', $label = true, $force_value = null ) {
		$disabled = $disabled || $this->_config->is_sealed( $option_id );
		$name     = Util_Ui::config_key_to_http_name( $option_id );

		if ( ! $disabled ) {
			echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="0" />';
		}

		if ( $label ) {
			echo '<label>';
		}

		echo '<input class="' . esc_attr( $class_prefix ) . 'enabled" type="checkbox" id="' . esc_attr( $name ) . '" name="' . esc_attr( $name ) . '" value="1" ';

		if ( ! is_null( $force_value ) ) {
			checked( $force_value, true );
		} elseif ( 'cdn.flush_manually' === $option_id ) {
			checked(
				$this->_config->get_boolean(
					$option_id,
					Cdn_Util::get_flush_manually_default_override( $this->_config->get_string( 'cdn.engine' ) )
				),
				true
			);
		} else {
			checked( $this->_config->get_boolean( $option_id ), true );
		}

		if ( $disabled ) {
			echo 'disabled="disabled" ';
		}

		echo ' />';
	}

	/**
	 * Prints a radio button and if config value matches value
	 *
	 * @param string  $option_id    Option id.
	 * @param unknown $value        Value.
	 * @param bool    $disabled     Disabled flag.
	 * @param string  $class_prefix Class prefix.
	 */
	protected function radio( $option_id, $value, $disabled = false, $class_prefix = '' ) {
		if ( is_bool( $value ) ) {
			$r_value = $value ? '1' : '0';
		} else {
			$r_value = $value;
		}

		$disabled = $disabled || $this->_config->is_sealed( $option_id );
		$name     = Util_Ui::config_key_to_http_name( $option_id );

		echo '<label>';
		echo '<input class="' . esc_attr( $class_prefix ) . 'enabled" type="radio" id="' . esc_attr( $name ) . '" name="' . esc_attr( $name ) . '" value="' . esc_attr( $r_value ) . '" ';

		checked( $this->_config->get_boolean( $option_id ), $value );

		if ( $disabled ) {
			echo 'disabled="disabled" ';
		}

		echo ' />';
	}

	/**
	 * Prints checkbox for debug option.
	 *
	 * @param string $option_id Option ID.
	 */
	protected function checkbox_debug( $option_id ) {
		if ( is_array( $option_id ) ) {
			$section         = $option_id[0];
			$section_enabled = $this->_config->is_extension_active_frontend( $section );
		} else {
			$section         = substr( $option_id, 0, strrpos( $option_id, '.' ) );
			$section_enabled = $this->_config->get_boolean( $section . '.enabled' );
		}

		$disabled = $this->_config->is_sealed( $option_id ) || ! $section_enabled;
		$name     = Util_Ui::config_key_to_http_name( $option_id );

		if ( ! $disabled ) {
			echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="0" />';
		}

		echo '<label>';
		echo '<input class="enabled" type="checkbox" id="' . esc_attr( $name ) . '" name="' . esc_attr( $name ) . '" value="1" ';

		checked( $this->_config->get_boolean( $option_id ) && $section_enabled, true );

		if ( $disabled ) {
			echo 'disabled="disabled" ';
		}

		echo ' />';
	}

	/**
	 * Prints checkbox for debug option for pro.
	 *
	 * @param string  $option_id Option ID.
	 * @param unknown $label     Label.
	 * @param unknown $label_pro Pro label.
	 */
	protected function checkbox_debug_pro( $option_id, $label, $label_pro ) {
		if ( is_array( $option_id ) ) {
			$section         = $option_id[0];
			$section_enabled = $this->_config->is_extension_active_frontend( $section );
		} else {
			$section         = substr( $option_id, 0, strrpos( $option_id, '.' ) );
			$section_enabled = $this->_config->get_boolean( $section . '.enabled' );
		}

		$is_pro   = Util_Environment::is_w3tc_pro( $this->_config );
		$disabled = $this->_config->is_sealed( $option_id ) || ! $section_enabled || ! $is_pro;
		$name     = Util_Ui::config_key_to_http_name( $option_id );

		if ( ! $disabled ) {
			echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="0" />';
		}

		echo '<label>';
		echo '<input class="enabled" type="checkbox" id="' . esc_attr( $name ) . '" name="' . esc_attr( $name ) . '" value="1" ';

		checked( $this->_config->get_boolean( $option_id ) && $is_pro, true );

		if ( $disabled ) {
			echo 'disabled="disabled" ';
		}

		echo ' />';
		echo esc_html( $label );

		if ( $is_pro ) {
			echo wp_kses(
				$label_pro,
				array(
					'a' => array(
						'href'  => array(),
						'id'    => array(),
						'class' => array(),
					),
				)
			);
		}

		echo '</label>';
	}

	/**
	 * Prints checkbox for debug option for pro.
	 *
	 * @param string  $option_id           Option ID.
	 * @param bool    $disabled            Disabled flag.
	 * @param unknown $value_when_disabled Override value when disabled.
	 */
	protected function value_with_disabled( $option_id, $disabled, $value_when_disabled ) {
		if ( $disabled ) {
			echo 'value="' . esc_attr( $value_when_disabled ) . '" disabled="disabled" ';
		} else {
			echo 'value="' . esc_attr( $this->_config->get_string( $option_id ) ) . '" ';
		}
	}

	/**
	 * Render header.
	 */
	protected function view() {
		include W3TC_INC_DIR . '/options/common/header.php';
	}
}
