<?php
/**
 * Embed support for Inline PDFs
 *
 * Takes a plain-text PDF URL (*.pdf), and attempts to embed it directly
 * in the post instead of leaving it as a bare link.
 *
 * @package automattic/jetpack
 */

wp_embed_register_handler( 'inline-pdfs', '#https?://[^<]*\.pdf$#i', 'jetpack_inline_pdf_embed_handler' );

/**
 * Callback to modify the output of embedded PDF files.
 *
 * @param array $matches Regex partial matches against the URL passed.
 * @param array $attr    Attributes received in embed response.
 * @param array $url     Requested URL to be embedded.
 */
function jetpack_inline_pdf_embed_handler( $matches, $attr, $url ) {
	/** This action is documented in modules/widgets/social-media-icons.php */
	do_action( 'jetpack_bump_stats_extras', 'embeds', 'inline-pdf' );

	$filename      = basename( wp_parse_url( $url, PHP_URL_PATH ) );
	$fallback_text = sprintf(
		/* translators: Placeholder is a file name, for example "file.pdf" */
		esc_html__( 'Click to access %1$s', 'jetpack' ),
		$filename
	);

	return sprintf(
		'<p><a href="%1$s" target="_blank" rel="noopener noreferrer nofollow">%2$s</a></p>',
		esc_url( $url ),
		$fallback_text
	);
}
