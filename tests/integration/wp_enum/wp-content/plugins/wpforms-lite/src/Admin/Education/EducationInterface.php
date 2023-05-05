<?php

namespace WPForms\Admin\Education;

/**
 * Interface EducationInterface defines required methods for Education features to work properly.
 *
 * @since 1.6.6
 */
interface EducationInterface {

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function allow_load();

	/**
	 * Init.
	 *
	 * @since 1.6.6
	 */
	public function init();
}
