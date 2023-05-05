<?php
/**
 * Site Editor - Show a snackbar indicating what's being edited.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\SiteEditorSnackbars;

const FEATURE_NAME = 'site-editor-snackbars';

add_filter(
	'jetpack_set_available_extensions',
	function ( $extensions ) {
		return array_merge(
			$extensions,
			array(
				FEATURE_NAME,
			)
		);
	}
);

add_action(
	'jetpack_register_gutenberg_extensions',
	function () {
		\Jetpack_Gutenberg::set_extension_available( FEATURE_NAME );
	}
);
