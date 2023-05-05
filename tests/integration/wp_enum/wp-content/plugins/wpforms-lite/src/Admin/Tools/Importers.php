<?php

namespace WPForms\Admin\Tools;

use WPForms\Admin\Tools\Importers\ContactForm7;
use WPForms\Admin\Tools\Importers\NinjaForms;
use WPForms\Admin\Tools\Importers\PirateForms;

/**
 * Load the different form importers.
 *
 * @since 1.6.6
 */
class Importers {

	/**
	 * Available importers.
	 *
	 * @since 1.6.6
	 *
	 * @var array
	 */
	private $importers = [];

	/**
	 * Load default form importers.
	 *
	 * @since 1.6.6
	 */
	public function load() {

		if ( empty( $this->importers ) ) {
			$this->importers = [
				'contact-form-7' => new ContactForm7(),
				'ninja-forms'    => new NinjaForms(),
				'pirate-forms'   => new PirateForms(),
			];
		}
	}

	/**
	 * Load default form importers.
	 *
	 * @since 1.6.6
	 *
	 * @return array
	 */
	public function get_importers() {

		$this->load();

		$importers = [];

		foreach ( $this->importers as $importer ) {
			$importers = $importer->register( $importers );
		}

		return apply_filters( 'wpforms_importers', $importers );
	}

	/**
	 * Get a importer forms.
	 *
	 * @since 1.6.6
	 *
	 * @param string $provider Provider.
	 *
	 * @return array
	 */
	public function get_importer_forms( $provider ) {

		if ( isset( $this->importers[ $provider ] ) ) {
			return apply_filters( "wpforms_importer_forms_{$provider}", $this->importers[ $provider ]->get_forms() );
		}

		return [];
	}

}
