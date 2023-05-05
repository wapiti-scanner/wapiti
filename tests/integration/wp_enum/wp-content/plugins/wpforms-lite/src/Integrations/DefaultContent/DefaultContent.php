<?php

namespace WPForms\Integrations\DefaultContent;

use WPForms\Integrations\IntegrationInterface;

/**
 * Class DefaultContent.
 *
 * @since 1.7.2
 */
class DefaultContent implements IntegrationInterface {

	/**
	 * Indicate if current integration is allowed to load.
	 *
	 * @since 1.7.2
	 *
	 * @return bool
	 */
	public function allow_load() {

		global $pagenow;

		return get_option( 'fresh_site' ) && $pagenow === 'customize.php';
	}

	/**
	 * Load an integration.
	 *
	 * @since 1.7.2
	 */
	public function load() {

		add_filter( 'get_theme_starter_content', [ $this, 'modify_starter_content' ], 1000, 2 );
	}

	/**
	 * Append education text to Contact page content.
	 *
	 * @since 1.7.2
	 *
	 * @param array $content Array of starter content.
	 * @param array $config  Array of theme-specific starter content configuration.
	 *
	 * @return array
	 */
	public function modify_starter_content( $content, $config ) {

		global $wp_version;

		if ( ! isset( $content['posts']['contact'] ) ) {
			return $content;
		}

		// Use Paragraph blocks for WP 5.0+.
		$format = version_compare( $wp_version, '5.0', '>=' ) ? "<!-- wp:paragraph -->\n<p>%s</p>\n<!-- /wp:paragraph -->" : '<p>%s</p>';

		$content['posts']['contact']['post_content'] .= sprintf(
			$format,
			wp_kses(
				sprintf( /* translators: %s - The WPForms Overview page URL. */
					_x( 'Create your <a href="%s" target="_blank" rel="noopener noreferrer">contact form</a> with WPForms in minutes.', 'Theme starter content', 'wpforms-lite' ),
					esc_url( admin_url( 'admin.php?page=wpforms-overview' ) )
				),
				[
					'a' => [
						'href'   => [],
						'rel'    => [],
						'target' => [],
					],
				]
			)
		);

		return $content;
	}
}
