<?php

namespace WPForms\Admin\Tools\Importers;

/**
 * Interface WPForms_Importer_Interface to handle common methods for all importers.
 *
 * @since 1.6.6
 */
interface ImporterInterface {

	/**
	 * Define required properties.
	 *
	 * @since 1.6.6
	 */
	public function init();

	/**
	 * Get ALL THE FORMS.
	 *
	 * @since 1.6.6
	 */
	public function get_forms();

	/**
	 * Get a single form.
	 *
	 * @since 1.6.6
	 *
	 * @param int $id Form ID.
	 */
	public function get_form( $id );

	/**
	 * Import a single form using AJAX.
	 *
	 * @since 1.6.6
	 */
	public function import_form();

	/**
	 * Replace 3rd-party form provider tags/shortcodes with our own Smart Tags.
	 *
	 * @since 1.6.6
	 *
	 * @param string $string Text to look for Smart Tags in.
	 * @param array  $fields List of fields to process Smart Tags in.
	 *
	 * @return string
	 */
	public function get_smarttags( $string, $fields );
}
