<?php
/**
 * Pay with PayPal block (aka Simple Payments).
 *
 * @since 9.0.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\SimplePayments;

use Automattic\Jetpack\Blocks;
use Jetpack_Simple_Payments;

const FEATURE_NAME = 'simple-payments';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array(
			'render_callback' => __NAMESPACE__ . '\render_block',
			'plan_check'      => true,
		)
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Pay with PayPal block dynamic rendering.
 *
 * @param array  $attr    Array containing the block attributes.
 * @param string $content String containing the block content.
 *
 * @return string
 */
function render_block( $attr, $content ) {
	// Do nothing if block content is a `simple-payment` shortcode.
	if ( preg_match( '/\[simple-payment(.*)]/', $content ) ) {
		return $content;
	}

	// Keep content as-is if rendered in other contexts than frontend (i.e. feed, emails, API, etc.).
	if ( ! jetpack_is_frontend() ) {
		return $content;
	}

	$simple_payments = Jetpack_Simple_Payments::get_instance();

	if ( ! $simple_payments->is_valid( $attr ) ) {
		return '';
	}

	$simple_payments->enqueue_frontend_assets();

	// For AMP requests, make sure the purchase link redirects to the non-AMP post URL.
	if ( Blocks::is_amp_request() ) {
		$content = preg_replace(
			'#(<a class="jetpack-simple-payments-purchase".*)rel="(.*)"(.*>.*</a>)#i',
			'$1rel="$2 noamphtml"$3',
			$content
		);
		return $content;
	}

	// Augment block UI with a PayPal button if rendered on the frontend.
	$product_id  = $attr['productId'];
	$dom_id      = wp_unique_id( "jetpack-simple-payments-{$product_id}_" );
	$is_multiple = get_post_meta( $product_id, 'spay_multiple', true ) || '0';

	$simple_payments->setup_paypal_checkout_button( $product_id, $dom_id, $is_multiple );

	$purchase_box = $simple_payments->output_purchase_box( $dom_id, $is_multiple );
	$content      = preg_replace( '#<a class="jetpack-simple-payments-purchase(.*)</a>#i', $purchase_box, $content );

	return $content;
}

/**
 * Determine if AMP should be disabled on posts having "Pay with PayPal" blocks.
 *
 * @param bool    $skip Skipped.
 * @param int     $post_id Post ID.
 * @param WP_Post $post Post.
 *
 * @return bool Whether to skip the post from AMP.
 */
function amp_skip_post( $skip, $post_id, $post ) {
	// When AMP is on standard mode, there are no non-AMP posts to link to where the purchase can be completed, so let's
	// prevent the post from being available in AMP.
	if ( function_exists( 'amp_is_canonical' ) && \amp_is_canonical() && has_block( BLOCK_NAME, $post->post_content ) ) {
		return true;
	}
	return $skip;
}
add_filter( 'amp_skip_post', __NAMESPACE__ . '\amp_skip_post', 10, 3 );
