<?php
/**
 * Helper functions that were deprecated and can be removed in future.
 *
 * @since 1.8.0
 */

/**
 * Get formatted [ id => title ] pages list.
 *
 * @since 1.7.2
 * @deprecated 1.7.9
 *
 * @todo Move to includes/deprecated.php
 *
 * @param array|string $args Array or string of arguments to retrieve pages.
 *
 * @return array
 */
function wpforms_get_pages_list( $args = [] ) {

	_deprecated_function( __FUNCTION__, '1.7.9 of the WPForms plugin' );

	$defaults = [
		'number' => 20,
	];
	$args     = wp_parse_args( $args, $defaults );
	$pages    = get_pages( $args );
	$list     = [];

	if ( empty( $pages ) ) {
		return $list;
	}

	foreach ( $pages as $page ) {
		$title             = wpforms_get_post_title( $page );
		$depth             = count( $page->ancestors );
		$list[ $page->ID ] = str_repeat( '&nbsp;', $depth * 3 ) . $title;
	}

	return $list;
}

/**
 * Dequeue enqueues by URI list.
 * Parts of URI (e.g. filename) is also supported.
 *
 * @since 1.6.1
 *
 * @param array|string         $uris     List of URIs or individual URI to dequeue.
 * @param WP_Scripts|WP_Styles $enqueues Enqueues list to dequeue from.
 */
function wpforms_dequeue_by_uri( $uris, $enqueues ) {

	if ( empty( $enqueues->queue ) ) {
		return;
	}

	foreach ( $enqueues->queue as $handle ) {

		if ( empty( $enqueues->registered[ $handle ]->src ) ) {
			continue;
		}

		$src = wp_make_link_relative( $enqueues->registered[ $handle ]->src );

		// Support full URLs.
		$src = site_url( $src );

		foreach ( (array) $uris as $uri ) {
			if ( strpos( $src, $uri ) !== false ) {
				wp_dequeue_script( $handle );
				break;
			}
		}
	}
}

/**
 * Dequeue scripts by URI list.
 * Parts of URI (e.g. filename) is also supported.
 *
 * @since 1.6.1
 *
 * @param array|string $uris List of URIs or individual URI to dequeue.
 */
function wpforms_dequeue_scripts_by_uri( $uris ) {

	wpforms_dequeue_by_uri( $uris, wp_scripts() );
}

/**
 * Dequeue styles by URI list.
 * Parts of URI (e.g. filename) is also supported.
 *
 * @since 1.6.1
 *
 * @param array|string $uris List of URIs or individual URI to dequeue.
 */
function wpforms_dequeue_styles_by_uri( $uris ) {

	wpforms_dequeue_by_uri( $uris, wp_styles() );
}

/**
 * Check if form provided contains Page Break, if so give details.
 *
 * @since 1.0.0
 *
 * @todo It is not used since 1.4.0. Probably, it should be deprecated and suggest using the wpforms_get_pagebreak_details() function.
 *
 * @param WP_Post|array $form Form data.
 *
 * @return int|bool Pages count or false.
 */
function wpforms_has_pagebreak( $form = false ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh

	if ( ! wpforms()->is_pro() ) {
		return false;
	}

	$form_data = '';
	$pagebreak = false;
	$pages     = 1;

	if ( is_object( $form ) && ! empty( $form->post_content ) ) {
		$form_data = wpforms_decode( $form->post_content );
	} elseif ( is_array( $form ) ) {
		$form_data = $form;
	}

	if ( empty( $form_data['fields'] ) ) {
		return false;
	}

	$fields = $form_data['fields'];

	foreach ( $fields as $field ) {

		if ( $field['type'] === 'pagebreak' && empty( $field['position'] ) ) {
			$pagebreak = true;

			$pages ++;
		}
	}

	if ( $pagebreak ) {
		return $pages;
	}

	return false;
}

/**
 * Try to find and return a top or bottom Page Break.
 *
 * @since 1.2.1
 *
 * @todo It is not used since 1.4.0. Probably, it should be deprecated and suggest using the wpforms_get_pagebreak_details() function.
 *
 * @param WP_Post|array $form Form data.
 * @param string|bool   $type Type of Page Break fields (top, bottom, pages or false).
 *
 * @return array|bool
 */
function wpforms_get_pagebreak( $form = false, $type = false ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.MaxExceeded

	if ( ! wpforms()->is_pro() ) {
		return false;
	}

	$form_data = '';

	if ( is_object( $form ) && ! empty( $form->post_content ) ) {
		$form_data = wpforms_decode( $form->post_content );
	} elseif ( is_array( $form ) ) {
		$form_data = $form;
	}

	if ( empty( $form_data['fields'] ) ) {
		return false;
	}

	$fields = $form_data['fields'];
	$pages  = [];

	foreach ( $fields as $field ) {

		if ( $field['type'] !== 'pagebreak' ) {
			continue;
		}

		$position = ! empty( $field['position'] ) ? $field['position'] : false;

		if ( $type === 'pages' && $position !== 'bottom' ) {
			$pages[] = $field;
		} elseif ( $position === $type ) {
			return $field;
		}
	}

	if ( ! empty( $pages ) ) {
		return $pages;
	}

	return false;
}

/**
 * Get meta key value for a form field.
 *
 * @since 1.1.9
 *
 * @param int|string $id        Field ID.
 * @param string     $key       Meta key.
 * @param mixed      $form_data Form data array.
 *
 * @return string
 */
function wpforms_get_form_field_meta( $id = '', $key = '', $form_data = '' ) {

	if ( empty( $id ) || empty( $key ) || empty( $form_data ) ) {
		return '';
	}

	if ( ! empty( $form_data['fields'][ $id ]['meta'][ $key ] ) ) {
		return $form_data['fields'][ $id ]['meta'][ $key ];
	}

	return '';
}

/**
 * Get an array of all possible provider addons.
 *
 * @since 1.5.5
 *
 * @return array
 */
function wpforms_get_providers_all() {

	return [
		[
			'name'        => 'ActiveCampaign',
			'slug'        => 'activecampaign',
			'img'         => 'addon-icon-activecampaign.png',
			'plugin'      => 'wpforms-activecampaign/wpforms-activecampaign.php',
			'plugin_slug' => 'wpforms-activecampaign',
			'license'     => 'elite',
		],
		[
			'name'        => 'AWeber',
			'slug'        => 'aweber',
			'img'         => 'addon-icon-aweber.png',
			'plugin'      => 'wpforms-aweber/wpforms-aweber.php',
			'plugin_slug' => 'wpforms-aweber',
			'license'     => 'pro',
		],
		[
			'name'        => 'Campaign Monitor',
			'slug'        => 'campaign-monitor',
			'img'         => 'addon-icon-campaign-monitor.png',
			'plugin'      => 'wpforms-campaign-monitor/wpforms-campaign-monitor.php',
			'plugin_slug' => 'wpforms-campaign-monitor',
			'license'     => 'pro',
		],
		[
			'name'        => 'Drip',
			'slug'        => 'drip',
			'img'         => 'addon-icon-drip.png',
			'plugin'      => 'wpforms-drip/wpforms-drip.php',
			'plugin_slug' => 'wpforms-drip',
			'license'     => 'pro',
		],
		[
			'name'        => 'GetResponse',
			'slug'        => 'getresponse',
			'img'         => 'addon-icon-getresponse.png',
			'plugin'      => 'wpforms-getresponse/wpforms-getresponse.php',
			'plugin_slug' => 'wpforms-getresponse',
			'license'     => 'pro',
		],
		[
			'name'        => 'Mailchimp',
			'slug'        => 'mailchimp',
			'img'         => 'addon-icon-mailchimp.png',
			'plugin'      => 'wpforms-mailchimp/wpforms-mailchimp.php',
			'plugin_slug' => 'wpforms-mailchimp',
			'license'     => 'pro',
		],
		[
			'name'        => 'Salesforce',
			'slug'        => 'salesforce',
			'img'         => 'addon-icon-salesforce.png',
			'plugin'      => 'wpforms-salesforce/wpforms-salesforce.php',
			'plugin_slug' => 'wpforms-salesforce',
			'license'     => 'elite',
		],
		[
			'name'        => 'Sendinblue',
			'slug'        => 'sendinblue',
			'img'         => 'addon-icon-sendinblue.png',
			'plugin'      => 'wpforms-sendinblue/wpforms-sendinblue.php',
			'plugin_slug' => 'wpforms-sendinblue',
			'license'     => 'pro',
		],
		[
			'name'        => 'Zapier',
			'slug'        => 'zapier',
			'img'         => 'addon-icon-zapier.png',
			'plugin'      => 'wpforms-zapier/wpforms-zapier.php',
			'plugin_slug' => 'wpforms-zapier',
			'license'     => 'pro',
		],
		[
			'name'        => 'HubSpot',
			'slug'        => 'hubspot',
			'img'         => 'addon-icon-hubspot.png',
			'plugin'      => 'wpforms-hubspot/wpforms-hubspot.php',
			'plugin_slug' => 'wpforms-hubspot',
			'license'     => 'pro',
		],
	];
}
