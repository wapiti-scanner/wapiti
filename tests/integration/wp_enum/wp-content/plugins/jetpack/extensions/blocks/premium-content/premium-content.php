<?php
/**
 * Premium Content Block.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Premium_Content;

use Automattic\Jetpack\Blocks;
use Automattic\Jetpack\Status\Host;
use Jetpack_Gutenberg;

require_once __DIR__ . '/_inc/access-check.php';
require_once __DIR__ . '/logged-out-view/logged-out-view.php';
require_once __DIR__ . '/subscriber-view/subscriber-view.php';
require_once __DIR__ . '/buttons/buttons.php';
require_once __DIR__ . '/login-button/login-button.php';

const FEATURE_NAME = 'premium-content/container';

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	// Only load this block on WordPress.com.
	if ( ( defined( 'IS_WPCOM' ) && IS_WPCOM ) || ( new Host() )->is_woa_site() ) {
		// Determine required `context` key based on Gutenberg version.
		$deprecated = function_exists( 'gutenberg_get_post_from_context' );
		$provides   = $deprecated ? 'providesContext' : 'provides_context';

		Blocks::jetpack_register_block(
			FEATURE_NAME,
			array(
				'render_callback' => __NAMESPACE__ . '\render_block',
				'plan_check'      => true,
				'attributes'      => array(
					'isPremiumContentChild' => array(
						'type'    => 'boolean',
						'default' => true,
					),
				),
				$provides         => array(
					'premium-content/planId' => 'selectedPlanId',
					'isPremiumContentChild'  => 'isPremiumContentChild',
				),
			)
		);
	}
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Render callback.
 *
 * @param array  $attributes Array containing the block attributes.
 * @param string $content    String containing the block content.
 *
 * @return string
 */
function render_block( $attributes, $content ) {
	if ( ! pre_render_checks() ) {
		return '';
	}

	if (
		! membership_checks()
		// Only display Stripe nudge if Upgrade nudge isn't displaying.
		&& required_plan_checks()
	) {
		$stripe_nudge = render_stripe_nudge();
		return $stripe_nudge . $content;
	}

	// We don't use FEATURE_NAME here because styles are not in /container folder.
	Jetpack_Gutenberg::load_assets_as_required( 'premium-content' );
	return $content;
}

/**
 * Server-side rendering for the stripe connection nudge.
 *
 * @return string Final content to render.
 */
function render_stripe_nudge() {
	if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
		\require_lib( 'memberships' );
		$blog_id  = get_current_blog_id();
		$settings = (array) \get_memberships_settings_for_site( $blog_id );

		return stripe_nudge(
			$settings['connect_url'],
			__( 'Connect to Stripe to use this block on your site.', 'jetpack' ),
			__( 'Connect', 'jetpack' )
		);
	} elseif ( ( new Host() )->is_woa_site() ) {
		// On WoA sites, the Stripe connection url is not easily available
		// server-side, so we redirect them to the post in the editor in order
		// to connect.
		return stripe_nudge(
			get_edit_post_link( get_the_ID() ),
			__( 'Connect to Stripe in the editor to use this block on your site.', 'jetpack' ),
			__( 'Edit post', 'jetpack' )
		);
	}

	// The Premium Content block is not supported on Jetpack sites.
	return '';
}

/**
 * Render the stripe nudge.
 *
 * @param string $checkout_url Url for the CTA.
 * @param string $description  Text of the nudge.
 * @param string $button_text  Text of the button.
 *
 * @return string Final content to render.
 */
function stripe_nudge( $checkout_url, $description, $button_text ) {
	require_once JETPACK__PLUGIN_DIR . '_inc/lib/components.php';
	return \Jetpack_Components::render_frontend_nudge(
		array(
			'checkoutUrl' => $checkout_url,
			'description' => $description,
			'buttonText'  => $button_text,
		)
	);
}
