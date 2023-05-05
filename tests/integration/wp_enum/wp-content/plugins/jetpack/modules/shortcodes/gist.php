<?php
/**
 * GitHub's Gist site supports oEmbed but their oembed provider only
 * returns raw HTML (no styling) and the first little bit of the code.
 *
 * Their JavaScript-based embed method is a lot better, so that's what we're using.
 *
 * Supported formats:
 * Full URL: https://gist.github.com/57cc50246aab776e110060926a2face2
 * Full URL with username: https://gist.github.com/jeherve/57cc50246aab776e110060926a2face2
 * Full URL linking to specific file: https://gist.github.com/jeherve/57cc50246aab776e110060926a2face2#file-wp-config-php
 * Full URL, no username, linking to specific file: https://gist.github.com/57cc50246aab776e110060926a2face2#file-wp-config-php
 * Gist ID: [gist]57cc50246aab776e110060926a2face2[/gist]
 * Gist ID within tag: [gist 57cc50246aab776e110060926a2face2]
 * Gist ID with username: [gist jeherve/57cc50246aab776e110060926a2face2]
 * Gist private ID with username: [gist xknown/fc5891af153e2cf365c9]
 *
 * @package automattic/jetpack
 */

wp_embed_register_handler( 'github-gist', '#https?://gist\.github\.com/([a-zA-Z0-9/]+)(\#file\-[a-zA-Z0-9\_\-]+)?#', 'github_gist_embed_handler' );
add_shortcode( 'gist', 'github_gist_shortcode' );

/**
 * Handle gist embeds.
 *
 * @since 2.8.0
 *
 * @global WP_Embed $wp_embed
 *
 * @param array  $matches Results after parsing the URL using the regex in wp_embed_register_handler().
 * @param array  $attr    Embed attributes.
 * @param string $url     The original URL that was matched by the regex.
 * @param array  $rawattr The original unmodified attributes.
 * @return string The embed HTML.
 */
function github_gist_embed_handler( $matches, $attr, $url, $rawattr ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
	// Let the shortcode callback do all the work.
	return github_gist_shortcode( $matches, $url );
}

/**
 * Extract an ID from a Gist shortcode or a full Gist URL.
 *
 * @since 7.3.0
 *
 * @param string $gist Gist shortcode or full Gist URL.
 *
 * @return array $gist_info {
 * Array of information about our gist.
 *     @type string $id   Unique identifier for the gist.
 *     @type string $file File name if the gist links to a specific file.
 * }
 */
function jetpack_gist_get_shortcode_id( $gist = '' ) {
	$gist_info = array(
		'id'   => '',
		'file' => '',
		'ts'   => 8,
	);
	// Simple shortcode, with just an ID.
	if ( ctype_alnum( $gist ) ) {
		$gist_info['id'] = $gist;
	}

	// Full URL? Only keep the relevant parts.
	$parsed_url = wp_parse_url( $gist );
	if (
		! empty( $parsed_url )
		&& is_array( $parsed_url )
		&& isset( $parsed_url['scheme'], $parsed_url['host'], $parsed_url['path'] )
	) {
		// Not a Gist URL? Bail.
		if ( 'gist.github.com' !== $parsed_url['host'] ) {
			return array(
				'id'   => '',
				'file' => '',
				'ts'   => 8,
			);
		}

		// Keep the file name if there was one.
		if ( ! empty( $parsed_url['fragment'] ) ) {
			$gist_info['file'] = preg_replace( '/(?:file-)(.+)/', '$1', $parsed_url['fragment'] );
		}

		// Keep the unique identifier without any leading or trailing slashes.
		if ( ! empty( $parsed_url['path'] ) ) {
			$gist_info['id'] = trim( $parsed_url['path'], '/' );
			// Overwrite $gist with our identifier to clean it up below.
			$gist = $gist_info['id'];
		}

		// Parse the query args to obtain the tab spacing.
		if ( ! empty( $parsed_url['query'] ) ) {
			$query_args = array();
			wp_parse_str( $parsed_url['query'], $query_args );
			if ( ! empty( $query_args['ts'] ) ) {
				$gist_info['ts'] = absint( $query_args['ts'] );
			}
		}
	}

	// Not a URL nor an ID? Look for "username/id", "/username/id", or "id", and only keep the ID.
	if ( preg_match( '#^/?(([a-z0-9_-]+/)?([a-z0-9]+))$#i', $gist, $matches ) ) {
		$gist_info['id'] = $matches[3];
	}

	return $gist_info;
}

/**
 * Callback for gist shortcode.
 *
 * @since 2.8.0
 *
 * @param array  $atts Attributes found in the shortcode.
 * @param string $content Content enclosed by the shortcode.
 *
 * @return string The gist HTML.
 */
function github_gist_shortcode( $atts, $content = '' ) {

	if ( empty( $atts[0] ) && empty( $content ) ) {
		if ( current_user_can( 'edit_posts' ) ) {
			return esc_html__( 'Please specify a Gist URL or ID.', 'jetpack' );
		} else {
			return '<!-- Missing Gist ID -->';
		}
	}

	$id = ( ! empty( $content ) ) ? $content : $atts[0];

	// Parse a URL to get an ID we can use.
	$gist_info = jetpack_gist_get_shortcode_id( $id );
	if ( empty( $gist_info['id'] ) ) {
		if ( current_user_can( 'edit_posts' ) ) {
			return esc_html__( 'The Gist ID you provided is not valid. Please try a different one.', 'jetpack' );
		} else {
			return '<!-- Invalid Gist ID -->';
		}
	} else {
		// Add trailing .json to all unique gist identifiers.
		$id = $gist_info['id'] . '.json';
	}

	// The file name can come from the URL passed, or from a shortcode attribute.
	if ( ! empty( $gist_info['file'] ) ) {
		$file = $gist_info['file'];
	} elseif ( ! empty( $atts['file'] ) ) {
		$file = $atts['file'];
	} else {
		$file = '';
	}

	// Replace - by . to get a real file name from slug.
	if ( ! empty( $file ) ) {
		// Find the last -.
		$dash_position = strrpos( $file, '-' );
		if ( false !== $dash_position ) {
			// Replace the - by a period.
			$file = substr_replace( $file, '.', $dash_position, 1 );
		}

		$file = rawurlencode( $file );
	}

	// Set the tab size, allowing attributes to override the query string.
	$tab_size = $gist_info['ts'];
	if ( ! empty( $atts['ts'] ) ) {
		$tab_size = absint( $atts['ts'] );
	}

	if (
		class_exists( 'Jetpack_AMP_Support' )
		&& Jetpack_AMP_Support::is_amp_request()
	) {
		/*
		 * According to <https://www.ampproject.org/docs/reference/components/amp-gist#height-(required)>:
		 *
		 * > Note: You must find the height of the gist by inspecting it with your browser (e.g., Chrome Developer Tools).
		 *
		 * However, this does not seem to be the case any longer. The actual height of the content does get set in the
		 * page after loading. So this is just the initial height.
		 * See <https://github.com/ampproject/amphtml/pull/17738>.
		 */
		$height = 240;

		$amp_tag = sprintf(
			'<amp-gist layout="fixed-height" data-gistid="%s" height="%s"',
			esc_attr( basename( $id, '.json' ) ),
			esc_attr( $height )
		);
		if ( ! empty( $file ) ) {
			$amp_tag .= sprintf( ' data-file="%s"', esc_attr( $file ) );
		}
		$amp_tag .= '></amp-gist>';
		return $amp_tag;
	}

	// URL points to the entire gist, including the file name if there was one.
	$id     = ( ! empty( $file ) ? $id . '?file=' . $file : $id );
	$return = false;

	$request      = wp_remote_get( esc_url_raw( 'https://gist.github.com/' . esc_attr( $id ) ) );
	$request_code = wp_remote_retrieve_response_code( $request );

	if ( 200 === $request_code ) {
		$request_body = wp_remote_retrieve_body( $request );
		$request_data = json_decode( $request_body );

		wp_enqueue_style( 'jetpack-gist-styling', esc_url( $request_data->stylesheet ), array(), JETPACK__VERSION );

		$gist = substr_replace( $request_data->div, sprintf( 'style="tab-size: %1$s" ', absint( $tab_size ) ), 5, 0 );

		// Add inline styles for the tab style in the opening div of the gist.
		$gist = preg_replace(
			'#(\<div\s)+(id=\"gist[0-9]+\")+(\sclass=\"gist\"\>)?#',
			sprintf( '$1style="tab-size: %1$s" $2$3', absint( $tab_size ) ),
			$request_data->div,
			1
		);

		// Add inline style to prevent the bottom margin to the embed that themes like TwentyTen, et al., add to tables.
		$return = sprintf( '<style>.gist table { margin-bottom: 0; }</style>%1$s', $gist );
	}

	if (
		// No need to check for a nonce here, that's already handled by Core further up.
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		isset( $_POST['type'] )
		&& 'embed' === $_POST['type']
		&& isset( $_POST['action'] )
		&& 'parse-embed' === $_POST['action']
		// phpcs:enable WordPress.Security.NonceVerification.Missing
	) {
		return github_gist_simple_embed( $id, $tab_size );
	}

	return $return;
}

/**
 * Use script tag to load shortcode in editor.
 * Can't use wp_enqueue_script here.
 *
 * @since 3.9.0
 *
 * @param string $id       The ID of the gist.
 * @param int    $tab_size The tab size of the gist.
 * @return string          The script tag of the gist.
 */
function github_gist_simple_embed( $id, $tab_size = 8 ) {
	$id = str_replace( 'json', 'js', $id );
	return '<script src="' . esc_url( "https://gist.github.com/$id?ts=$tab_size" ) . '"></script>'; // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript
}
