<?php

namespace WPForms\Providers\Provider\Settings;

/**
 * Interface PageIntegrationsInterface defines methods that are common among all Integration page providers content.
 *
 * @since 1.4.7
 */
interface PageIntegrationsInterface {

	/**
	 * Display the data for integrations tab.
	 * This is a default one, that can be easily overwritten inside the child class of a specific provider.
	 *
	 * @since 1.4.7
	 *
	 * @param array $active Array of activated providers addons.
	 * @param array $settings Providers options.
	 */
	public function display( $active, $settings );
}
