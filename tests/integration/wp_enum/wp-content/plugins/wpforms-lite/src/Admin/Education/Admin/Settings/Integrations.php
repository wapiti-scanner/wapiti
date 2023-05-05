<?php

namespace WPForms\Admin\Education\Admin\Settings;

use \WPForms\Admin\Education\AddonsListBase;

/**
 * Base class for Admin/Integrations feature for Lite and Pro.
 *
 * @since 1.6.6
 */
class Integrations extends AddonsListBase {

	/**
	 * Template for rendering single addon item.
	 *
	 * @since 1.6.6
	 *
	 * @var string
	 */
	protected $single_addon_template = 'education/admin/settings/integrations-item';

	/**
	 * Hooks.
	 *
	 * @since 1.6.6
	 */
	public function hooks() {

		add_action( 'wpforms_settings_providers', [ $this, 'filter_addons' ], 1 );
		add_action( 'wpforms_settings_providers', [ $this, 'display_addons' ], 500 );
	}

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function allow_load() {

		return wpforms_is_admin_page( 'settings', 'integrations' );
	}

	/**
	 * Get addons for the Settings/Integrations tab.
	 *
	 * @since 1.6.6
	 *
	 * @return array Addons data.
	 */
	protected function get_addons() {

		return $this->addons->get_by_category( 'providers' );
	}

	/**
	 * Ensure that we do not display activated addon items if those addons are not allowed according to the current license.
	 *
	 * @since 1.6.6
	 */
	public function filter_addons() {

		$this->filter_not_allowed_addons( 'wpforms_settings_providers' );
	}
}
