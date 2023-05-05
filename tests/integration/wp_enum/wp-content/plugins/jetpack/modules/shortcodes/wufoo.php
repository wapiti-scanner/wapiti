<?php
/**
 * Plugin Name: Wufoo Shortcode
 * Based on https://wordpress.org/plugins/wufoo-shortcode/
 *
 * Examples:
 * [wufoo username="jeherve" formhash="z1x13ltw1m8jtrw" autoresize="true" height="338" header="show"]
 *
 * @package automattic/jetpack
 */

/**
 * Display the Wufoo shortcode.
 *
 * @param array $atts Shortcode attributes.
 */
function wufoo_shortcode( $atts ) {
	$attr = shortcode_atts(
		array(
			'username'   => '',
			'formhash'   => '',
			'autoresize' => true,
			'height'     => '500',
			'header'     => 'show',
		),
		$atts
	);

	// Check username and formhash to ensure they only have alphanumeric characters or underscores, and aren't empty.
	if (
		! preg_match( '/^[a-zA-Z0-9_]+$/', $attr['username'] )
		|| ! preg_match( '/^[a-zA-Z0-9_]+$/', $attr['formhash'] )
	) {
		/*
		 * Return an error to the users with instructions if one of these params is invalid
		 * They don't have default values because they are user/form-specific
		 */
		if ( current_user_can( 'edit_posts' ) ) {
			return sprintf(
				wp_kses(
					/* translators: URL to Wufoo support page. */
					__( 'Something is wrong with your Wufoo shortcode. Try following the instructions <a href="%s" target="_blank" rel="noopener noreferrer">here</a> to embed a form on your site.', 'jetpack' ),
					array(
						'a' => array(
							'href'   => array(),
							'target' => array(),
							'rel'    => array(),
						),
					)
				),
				'https://help.wufoo.com/articles/en_US/kb/Embed'
			);
		}

		return;
	}

	/**
	 * Placeholder which will tell Wufoo where to render the form.
	 */
	$js_embed_placeholder = sprintf(
		'<div id="wufoo-%s"></div>',
		esc_attr( $attr['formhash'] )
	);

	/**
	 * Required parameters are present.
	 * An error will be returned inside the form if they are invalid.
	 */
	$js_embed = sprintf(
		'(function(){try{var wufoo_%1$s = new WufooForm();wufoo_%1$s.initialize({"userName":"%2$s","formHash":"%1$s","autoResize":%3$s,"height":"%4$d","header":"%5$s","ssl":true,"async":true});wufoo_%1$s.display();}catch(e){}})();',
		esc_attr( $attr['formhash'] ),
		esc_attr( $attr['username'] ),
		'true' == $attr['autoresize'] ? 'true' : 'false', // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
		absint( $attr['height'] ),
		'show' === $attr['header'] ? 'show' : 'hide'
	);

	// Embed URL.
	$embed_url = sprintf(
		'https://%1$s.wufoo.com/embed/%2$s/',
		$attr['username'],
		$attr['formhash']
	);

	// Form URL.
	$form_url = sprintf(
		'https://%1$s.wufoo.com/forms/%2$s/',
		$attr['username'],
		$attr['formhash']
	);

	/*
	 * iframe embed, loaded inside <noscript> tags.
	 */
	$iframe_embed = sprintf(
		'<iframe height="%1$d" src="%2$s" allowTransparency="true" frameborder="0" scrolling="no" style="width:100%%;border:none;">
			<a href="%3$s" target="_blank" rel="noopener noreferrer">%4$s</a>
		</iframe>',
		absint( $attr['height'] ),
		esc_url( $embed_url ),
		esc_url( $form_url ),
		esc_html__( 'Fill out my Wufoo form!', 'jetpack' )
	);

	wp_enqueue_script(
		'wufoo-form',
		'https://www.wufoo.com/scripts/embed/form.js',
		array(),
		JETPACK__VERSION,
		true
	);
	wp_add_inline_script( 'wufoo-form', $js_embed );

	/** This action is already documented in modules/widgets/gravatar-profile.php */
	do_action( 'jetpack_stats_extra', 'embeds', 'wufoo' );

	/**
	 * Return embed in JS and iframe.
	 */
	return "$js_embed_placeholder<noscript>$iframe_embed</noscript>";
}
add_shortcode( 'wufoo', 'wufoo_shortcode' );
