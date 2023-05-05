<?php
/**
 * This file contains compatibility functions for WooCommerce to improve Jetpack feature support.
 *
 * @package automattic/jetpack
 */

add_action( 'woocommerce_init', 'jetpack_woocommerce_integration' );

/**
 * Loads JP+WC integration.
 *
 * Fires on `woocommerce_init` hook
 */
function jetpack_woocommerce_integration() {
	/**
	 * Double check WooCommerce exists - unlikely to fail due to the hook being used but better safe than sorry.
	 */
	if ( ! class_exists( 'WooCommerce' ) ) {
		return;
	}

	add_action( 'woocommerce_share', 'jetpack_woocommerce_social_share_icons', 10 );

	/**
	 * Wrap in function exists check since this requires WooCommerce 3.3+.
	 */
	if ( function_exists( 'wc_get_default_products_per_row' ) ) {
		add_filter( 'infinite_scroll_render_callbacks', 'jetpack_woocommerce_infinite_scroll_render_callback', 10 );
		add_action( 'wp_enqueue_scripts', 'jetpack_woocommerce_infinite_scroll_style', 10 );
	}
}

/**
 * Make sure the social sharing icons show up under the product's short description
 */
function jetpack_woocommerce_social_share_icons() {
	if ( function_exists( 'sharing_display' ) ) {
		remove_filter( 'the_content', 'sharing_display', 19 );
		remove_filter( 'the_excerpt', 'sharing_display', 19 );
		sharing_display( '', true );
	}
}

/**
 * Remove sharing display from account, cart, and checkout pages in WooCommerce.
 */
function jetpack_woocommerce_remove_share() {
	/**
	 * Double check WooCommerce exists - unlikely to fail due to the hook being used but better safe than sorry.
	 */
	if ( ! class_exists( 'WooCommerce' ) ) {
		return;
	}

	if ( is_cart() || is_checkout() || is_account_page() ) {
		remove_filter( 'the_content', 'sharing_display', 19 );
		if ( class_exists( 'Jetpack_Likes' ) ) {
			remove_filter( 'the_content', array( Jetpack_Likes::init(), 'post_likes' ), 30, 1 );
		}
	}
}
add_action( 'loop_start', 'jetpack_woocommerce_remove_share' );

/**
 * Add a callback for WooCommerce product rendering in infinite scroll.
 *
 * @param array $callbacks Array of render callpacks for IS.
 * @return array
 */
function jetpack_woocommerce_infinite_scroll_render_callback( $callbacks ) {
	$callbacks[] = 'jetpack_woocommerce_infinite_scroll_render';
	return $callbacks;
}

/**
 * Add a default renderer for WooCommerce products within infinite scroll.
 */
function jetpack_woocommerce_infinite_scroll_render() {
	if ( ! is_shop() && ! is_product_taxonomy() && ! is_product_category() && ! is_product_tag() ) {
		return;
	}

	woocommerce_product_loop_start();

	while ( have_posts() ) {
		the_post();
		wc_get_template_part( 'content', 'product' );
	}

	woocommerce_product_loop_end();
}

/**
 * Basic styling when infinite scroll is active only.
 */
function jetpack_woocommerce_infinite_scroll_style() {
	$custom_css = '
	.infinite-scroll .woocommerce-pagination {
		display: none;
	}';
	wp_add_inline_style( 'woocommerce-layout', $custom_css );
}

/**
 * Adds compat for WooCommerce and Lazy Loading.
 */
function jetpack_woocommerce_lazy_images_compat() {
	wp_add_inline_script(
		'wc-cart-fragments',
		"
		jQuery( 'body' ).bind( 'wc_fragments_refreshed', function() {
			var jetpackLazyImagesLoadEvent;
			try {
				jetpackLazyImagesLoadEvent = new Event( 'jetpack-lazy-images-load', {
					bubbles: true,
					cancelable: true
				} );
			} catch ( e ) {
				jetpackLazyImagesLoadEvent = document.createEvent( 'Event' )
				jetpackLazyImagesLoadEvent.initEvent( 'jetpack-lazy-images-load', true, true );
			}
			jQuery( 'body' ).get( 0 ).dispatchEvent( jetpackLazyImagesLoadEvent );
		} );
		"
	);
}

add_action( 'wp_enqueue_scripts', 'jetpack_woocommerce_lazy_images_compat', 11 );
