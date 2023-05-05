<?php
/**
 * Generic helper functions.
 *
 * @since 1.8.0
 */

use WPForms\Helpers\Chain;

/**
 * Get a suffix for assets, `.min` if debug is disabled.
 *
 * @since 1.4.1
 *
 * @return string
 */
function wpforms_get_min_suffix() {

	return wpforms_debug() ? '' : '.min';
}

/**
 * Chain monad, useful for chaining certain array or string related functions.
 *
 * @since 1.5.6
 *
 * @param mixed $value Any data.
 *
 * @return Chain
 */
function wpforms_chain( $value ) {

	return Chain::of( $value );
}

/**
 * Convert object to an array.
 *
 * @since 1.1.7
 *
 * @param object $object Object to convert.
 *
 * @return mixed
 */
function wpforms_object_to_array( $object ) {

	if ( ! is_object( $object ) && ! is_array( $object ) ) {
		return $object;
	}

	if ( is_object( $object ) ) {
		$object = get_object_vars( $object );
	}

	return array_map( 'wpforms_object_to_array', $object );
}

/**
 * Insert an array into another array before/after a certain key.
 *
 * @link  https://gist.github.com/scribu/588429
 *
 * @since 1.3.9
 *
 * @param array  $array    The initial array.
 * @param array  $pairs    The array to insert.
 * @param string $key      The certain key.
 * @param string $position Where to insert the array - before or after the key.
 *
 * @return array
 */
function wpforms_array_insert( $array, $pairs, $key, $position = 'after' ) {

	$key_pos = array_search( $key, array_keys( $array ), true );

	if ( $position === 'after' ) {
		$key_pos ++;
	}

	if ( $key_pos !== false ) {
		$result = array_slice( $array, 0, $key_pos );
		$result = array_merge( $result, $pairs );
		$result = array_merge( $result, array_slice( $array, $key_pos ) );
	} else {
		$result = array_merge( $array, $pairs );
	}

	return $result;
}

/**
 * Recursively remove empty strings from an array.
 *
 * @since 1.3.9.1
 *
 * @param array $data Any data.
 *
 * @return array
 */
function wpforms_array_remove_empty_strings( $data ) {

	foreach ( $data as $key => $value ) {
		if ( is_array( $value ) ) {
			$data[ $key ] = wpforms_array_remove_empty_strings( $data[ $key ] );
		}

		if ( $data[ $key ] === '' ) {
			unset( $data[ $key ] );
		}
	}

	return $data;
}

/**
 * Count words in the string.
 *
 * @since 1.6.2
 *
 * @param string $string String value.
 *
 * @return integer Words count.
 */
function wpforms_count_words( $string ) {

	if ( ! is_string( $string ) ) {
		return 0;
	}

	$patterns = [
		'/([A-Z]+),([A-Z]+)/i',
		'/([0-9]+),([A-Z]+)/i',
		'/([A-Z]+),([0-9]+)/i',
	];

	foreach ( $patterns as $pattern ) {
		$string = preg_replace_callback(
			$pattern,
			function( $matches ) {
				return $matches[1] . ', ' . $matches[2];
			},
			$string
		);
	}

	$words = preg_split( '/[\s]+/', $string );

	return is_array( $words ) ? count( $words ) : 0;
}

/**
 * Link a list of words or phrases with commas, but the last one – with a conjunction.
 *
 * For example:
 * [ 'Sullie', 'Pattie', 'me' ] with 'and' conjunction becomes 'Sullie, Pattie and me'.
 * [ 'Sullie', 'Pattie', 'me' ] with 'or' conjunction becomes 'Sullie, Pattie or me'.
 *
 * @since 1.8.0
 *
 * @param array  $list        A list of words or phrases to link together.
 * @param string $conjunction Coordinating conjunction to use for last word or phrase (usually – and, or).
 *                            The string is expected to be translatable.
 *
 * @return string Linked words and/or phrases.
 */
function wpforms_conjunct( $list, $conjunction ) {

	$last_chunk = array_pop( $list );

	return $list ?
		sprintf( '%s %s %s', implode( ', ', $list ), $conjunction, $last_chunk ) :
		$last_chunk;
}

/**
 * Get the current URL.
 *
 * @since 1.0.0
 * @since 1.7.2 Refactored based on the `home_url` function.
 *
 * @return string
 */
function wpforms_current_url() {

	$parsed_home_url = wp_parse_url( home_url() );

	$url = $parsed_home_url['scheme'] . '://' . $parsed_home_url['host'];

	if ( ! empty( $parsed_home_url['port'] ) ) {
		$url .= ':' . $parsed_home_url['port'];
	}

	// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
	$url .= wp_unslash( $_SERVER['REQUEST_URI'] );

	return esc_url_raw( $url );
}

/**
 * Add UTM tags to a link that allows detecting traffic sources for our or partners' websites.
 *
 * @since 1.7.5
 *
 * @param string $link    Link to which you need to add UTM tags.
 * @param string $medium  The page or location description. Check your current page and try to find
 *                        and use an already existing medium for links otherwise, use a page name.
 * @param string $content The feature's name, the button's content, the link's text, or something
 *                        else that describes the element that contains the link.
 * @param string $term    Additional information for the content that makes the link more unique.
 *
 * @return string
 */
function wpforms_utm_link( $link, $medium, $content = '', $term = '' ) {

	return add_query_arg(
		array_filter(
			[
				'utm_campaign' => wpforms()->is_pro() ? 'plugin' : 'liteplugin',
				'utm_source'   => strpos( $link, 'https://wpforms.com' ) === 0 ? 'WordPress' : 'wpformsplugin',
				'utm_medium'   => rawurlencode( $medium ),
				'utm_content'  => rawurlencode( $content ),
				'utm_term'     => rawurlencode( $term ),
				'utm_locale'   => wpforms_sanitize_key( get_locale() ),
			]
		),
		$link
	);
}

/**
 * Modify the default USer-Agent generated by wp_remote_*() to include additional information.
 *
 * @since 1.7.5.2
 *
 * @return string
 */
function wpforms_get_default_user_agent() {

	$license_type = wpforms()->is_pro() ? ucwords( (string) wpforms_get_license_type() ) : 'Lite';

	return 'WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' ) . '; WPForms/' . $license_type . '-' . WPFORMS_VERSION;
}

/**
 * Get the ISO 639-2 Language Code from user/site locale.
 *
 * @see http://www.loc.gov/standards/iso639-2/php/code_list.php
 *
 * @since 1.5.0
 *
 * @return string
 */
function wpforms_get_language_code() {

	$default_lang = 'en';
	$locale       = get_user_locale();

	if ( ! empty( $locale ) ) {
		$lang = explode( '_', $locale );

		if ( ! empty( $lang ) && is_array( $lang ) ) {
			$default_lang = strtolower( $lang[0] );
		}
	}

	return $default_lang;
}

/**
 * Changes array of items into string of items, separated by comma and sql-escaped.
 *
 * @see https://coderwall.com/p/zepnaw
 *
 * @since 1.7.4
 *
 * @param mixed|array $items  Item(s) to be joined into string.
 * @param string      $format Can be %s or %d.
 *
 * @return string Items separated by comma and sql-escaped.
 */
function wpforms_wpdb_prepare_in( $items, $format = '%s' ) {

	global $wpdb;

	$items    = (array) $items;
	$how_many = count( $items );

	if ( $how_many === 0 ) {
		return '';
	}

	$placeholders    = array_fill( 0, $how_many, $format );
	$prepared_format = implode( ',', $placeholders );

	// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
	return $wpdb->prepare( $prepared_format, $items );
}

/**
 * Get the render engine slug according to the Modern Markup setting value and corresponding filter.
 *
 * @since 1.8.1
 *
 * @return string
 */
function wpforms_get_render_engine() {

	$render_engine = empty( wpforms_setting( 'modern-markup', false ) ) ? 'classic' : 'modern';

	/**
	 * Filter current render engine slug.
	 * Allows addons to use their own frontend rendering engine.
	 *
	 * @since 1.8.1
	 *
	 * @param string $render_engine Render engine slug.
	 */
	$render_engine = apply_filters( 'wpforms_get_render_engine', $render_engine );

	return $render_engine;
}
