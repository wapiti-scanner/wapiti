<?php

namespace WPForms\Admin\Pages;

/**
 * Community Sub-page.
 *
 * @since 1.5.6
 */
class Community {

	/**
	 * Admin menu page slug.
	 *
	 * @since 1.5.6
	 *
	 * @var string
	 */
	const SLUG = 'wpforms-community';

	/**
	 * Constructor.
	 *
	 * @since 1.5.6
	 */
	public function __construct() {

		if ( \wpforms_current_user_can() ) {
			$this->hooks();
		}
	}

	/**
	 * Hooks.
	 *
	 * @since 1.5.6
	 */
	public function hooks() {

		// Check what page we are on.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.CSRF.NonceVerification

		// Only load if we are actually on the Community page.
		if ( self::SLUG !== $page ) {
			return;
		}

		add_action( 'wpforms_admin_page', [ $this, 'output' ] );

		// Hook for addons.
		do_action( 'wpforms_admin_community_init' );
	}

	/**
	 * Page data.
	 *
	 * @since 1.5.6
	 */
	public function get_blocks_data() {

		$type = wpforms()->is_pro() ? 'plugin' : 'liteplugin';
		$data = [];

		$data['vip_circle'] = [
			'title'          => esc_html__( 'WPForms VIP Circle Facebook Group', 'wpforms-lite' ),
			'description'    => esc_html__( 'Powered by the community, for the community. Anything and everything WPForms: Discussions. Questions. Tutorials. Insights and sneak peaks. Also, exclusive giveaways!', 'wpforms-lite' ),
			'button_text'    => esc_html__( 'Join WPForms VIP Circle', 'wpforms-lite' ),
			'button_link'    => 'https://www.facebook.com/groups/wpformsvip/',
			'cover_bg_color' => '#E4F0F6',
			'cover_img'      => 'vip-circle.png',
			'cover_img2x'    => 'vip-circle@2x.png',
		];

		$data['youtube'] = [
			'title'          => esc_html__( 'WPForms YouTube Channel', 'wpforms-lite' ),
			'description'    => esc_html__( 'Take a visual dive into everything WPForms has to offer. From simple contact forms to advanced payment forms and email marketing integrations, our extensive video collection covers it all.', 'wpforms-lite' ),
			'button_text'    => esc_html__( 'Visit WPForms YouTube Channel', 'wpforms-lite' ),
			'button_link'    => 'https://www.youtube.com/c/wpformsplugin',
			'cover_bg_color' => '#FFE6E6',
			'cover_img'      => 'youtube.png',
			'cover_img2x'    => 'youtube@2x.png',
		];

		$data['dev_docs'] = [
			'title'          => esc_html__( 'WPForms Developer Documentation', 'wpforms-lite' ),
			'description'    => esc_html__( 'Customize and extend WPForms with code. Our comprehensive developer resources include tutorials, snippets, and documentation on core actions, filters, functions, and more.', 'wpforms-lite' ),
			'button_text'    => esc_html__( 'View WPForms Dev Docs', 'wpforms-lite' ),
			'button_link'    => 'https://wpforms.com/developers/?utm_source=WordPress&amp;utm_medium=Community&amp;utm_campaign=' . esc_attr( $type ) . '&amp;utm_content=Developers',
			'cover_bg_color' => '#EBEBEB',
			'cover_img'      => 'dev-docs.png',
			'cover_img2x'    => 'dev-docs@2x.png',
		];

		$data['wpbeginner'] = [
			'title'          => esc_html__( 'WPBeginner Engage Facebook Group', 'wpforms-lite' ),
			'description'    => esc_html__( 'Hang out with other WordPress experts and like minded website owners such as yourself! Hosted by WPBeginner, the largest free WordPress site for beginners.', 'wpforms-lite' ),
			'button_text'    => esc_html__( 'Join WPBeginner Engage', 'wpforms-lite' ),
			'button_link'    => 'https://www.facebook.com/groups/wpbeginner/',
			'cover_bg_color' => '#FCEBDF',
			'cover_img'      => 'wpbeginner.png',
			'cover_img2x'    => 'wpbeginner@2x.png',
		];

		$data['suggest'] = [
			'title'          => esc_html__( 'Suggest a Feature', 'wpforms-lite' ),
			'description'    => esc_html__( 'Do you have an idea or suggestion for WPForms? If you have thoughts on features, integrations, addons, or improvements - we want to hear it! We appreciate all feedback and insight from our users.', 'wpforms-lite' ),
			'button_text'    => esc_html__( 'Suggest a Feature', 'wpforms-lite' ),
			'button_link'    => 'https://wpforms.com/features/suggest/?utm_source=WordPress&amp;utm_medium=Community&amp;utm_campaign=' . esc_attr( $type ) . '&amp;utm_content=Feature',
			'cover_bg_color' => '#FFF9EF',
			'cover_img'      => 'suggest.png',
			'cover_img2x'    => 'suggest@2x.png',
		];

		return $data;
	}

	/**
	 * Generate and output page HTML.
	 *
	 * @since 1.5.6
	 */
	public function output() {

		?>
		<div id="wpforms-admin-community" class="wrap wpforms-admin-wrap">
			<h1 class="page-title"><?php esc_html_e( 'Community', 'wpforms-lite' ); ?></h1>
			<div class="items">
				<?php
				$data = $this->get_blocks_data();

				foreach ( $data as $item ) {
					printf(
						'<div class="item">
							<a href="%6$s" target="_blank" rel="noopener noreferrer" class="item-cover" style="background-color: %s;" title="%4$s"><img class="item-img" src="%s" srcset="%s 2x" alt="%4$s"/></a>
							<h3 class="item-title">%s</h3>
							<p class="item-description">%s</p>
							<div class="item-footer">
								<a class="button-primary" href="%s" target="_blank" rel="noopener noreferrer">%s</a>
							</div>
						</div>',
						esc_attr( $item['cover_bg_color'] ),
						esc_url( WPFORMS_PLUGIN_URL . 'assets/images/community/' . $item['cover_img'] ),
						esc_url( WPFORMS_PLUGIN_URL . 'assets/images/community/' . $item['cover_img2x'] ),
						esc_html( $item['title'] ),
						esc_html( $item['description'] ),
						esc_url( $item['button_link'] ),
						esc_html( $item['button_text'] )
					);
				}
				?>
			</div>
		</div>
		<?php
	}
}
