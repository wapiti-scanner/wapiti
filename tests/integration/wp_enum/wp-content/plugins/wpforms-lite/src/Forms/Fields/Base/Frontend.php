<?php

namespace WPForms\Forms\Fields\Base;

use WPForms_Field;

/**
 * Field's Frontend base class.
 *
 * @since 1.8.1
 */
class Frontend {

	/**
	 * Instance of the main WPForms_Field_{something} class.
	 *
	 * @since 1.8.1
	 *
	 * @var WPForms_Field
	 */
	protected $field_obj;

	/**
	 * Class constructor.
	 *
	 * @since 1.8.1
	 *
	 * @param WPForms_Field $field_obj Instance of the WPForms_Field_{something} class.
	 */
	public function __construct( $field_obj ) {

		$this->field_obj = $field_obj;

		$this->init();
	}

	/**
	 * Initialize.
	 *
	 * @since 1.8.1
	 */
	public function init() {

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.8.1
	 */
	protected function hooks() {
	}
}
