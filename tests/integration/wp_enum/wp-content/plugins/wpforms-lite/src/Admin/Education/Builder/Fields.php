<?php

namespace WPForms\Admin\Education\Builder;

use \WPForms\Admin\Education\AddonsItemBase;

/**
 * Base class for Builder/Fields Education feature.
 *
 * @since 1.6.6
 */
abstract class Fields extends AddonsItemBase {

	/**
	 * Instance of the Education\Fields class.
	 *
	 * @since 1.6.6
	 *
	 * @var \WPForms\Admin\Education\Fields
	 */
	protected $fields;

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function allow_load() {

		return wp_doing_ajax() || wpforms_is_admin_page( 'builder' );
	}

	/**
	 * Init.
	 *
	 * @since 1.6.6
	 */
	public function init() {

		parent::init();

		// Store the instance of the Education\Fields class.
		$this->fields = wpforms()->get( 'education_fields' );
	}
}
