<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * CSS preprocessor registration.
 *
 * To add a new preprocessor (or replace an existing one), hook into the
 * jetpack_custom_css_preprocessors filter and add an entry to the array
 * that is passed in.
 *
 * Format is:
 * $preprocessors[ UNIQUE_KEY ] => array( 'name' => 'Processor name', 'callback' => [processing function] );
 *
 * The callback function accepts a single string argument (non-CSS markup) and returns a string (CSS).
 *
 * @param array $preprocessors The list of preprocessors added thus far.
 * @return array
 */
function jetpack_register_css_preprocessors( $preprocessors ) {
	$preprocessors['less'] = array(
		'name'     => 'LESS',
		'callback' => 'jetpack_less_css_preprocess',
	);

	$preprocessors['sass'] = array(
		'name'     => 'Sass (SCSS Syntax)',
		'callback' => 'jetpack_sass_css_preprocess',
	);

	return $preprocessors;
}

add_filter( 'jetpack_custom_css_preprocessors', 'jetpack_register_css_preprocessors' );

/**
 * Compile less prepocessors?
 *
 * @param string $less - less.
 */
function jetpack_less_css_preprocess( $less ) {
	require_once __DIR__ . '/preprocessors/lessc.inc.php';

	$compiler = new lessc();

	try {
		return $compiler->compile( $less );
	} catch ( Exception $e ) {
		return $less;
	}
}

/**
 * Compile sass prepocessors?
 *
 * @param string $sass - sass.
 */
function jetpack_sass_css_preprocess( $sass ) {
	require_once __DIR__ . '/preprocessors/scss.inc.php';

	$compiler = new scssc();
	$compiler->setFormatter( 'scss_formatter' );

	try {
		return $compiler->compile( $sass );
	} catch ( Exception $e ) {
		return $sass;
	}
}
