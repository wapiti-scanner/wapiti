<?php

namespace WPForms\Admin\Education\Builder;

use \WPForms\Admin\Education\AddonsListBase;

/**
 * Base class for Builder/Settings, Builder/Providers, Builder/Payments Education features.
 *
 * @since 1.6.6
 */
abstract class Panel extends AddonsListBase {

	/**
	 * Panel slug. Should be redefined in the real Builder/Panel class.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 **/
	abstract protected function get_name();

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function allow_load() {

		// Load only in the Form Builder.
		return wpforms_is_admin_page( 'builder' ) && ! empty( $this->get_name() );
	}

	/**
	 * Get addons for the current panel.
	 *
	 * @since 1.6.6
	 */
	protected function get_addons() {

		return $this->addons->get_by_category( $this->get_name() );
	}

	/**
	 * Template name for rendering single addon item.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	protected function get_single_addon_template() {

		return 'education/builder/' . $this->get_name() . '-item';
	}

	/**
	 * Display addons.
	 *
	 * @since 1.6.6
	 */
	public function display_addons() {

		$this->single_addon_template = $this->get_single_addon_template();

		parent::display_addons();
	}
}
