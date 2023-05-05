<?php
/**
 * File: FeatureShowcase_Plugin_Admin_View.php
 *
 * @since 2.1.0
 *
 * @package W3TC
 *
 * @uses array $config W3TC configuration.
 * @uses array $cards {
 *     Feature configuration.
 *
 *     @type string $title      Title.
 *     @type string $icon       Dashicon icon class.
 *     @type string $text       Description.
 *     @type string $button     Button markup.
 *     @type string $link       Link URL address.
 *     @type bool   $is_premium Is it a premium feature.
 * }
 *
 * @see Util_Environment::is_w3tc_pro()
 * @see Util_Ui::pro_wrap_maybe_end2()
 *
 * phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped
 */

namespace W3TC;

$is_pro = Util_Environment::is_w3tc_pro( $config );

if ( $is_pro ) {
	require W3TC_INC_DIR . '/options/common/header.php';
} else {
	require W3TC_INC_DIR . '/options/parts/dashboard_banner.php';
}

?>

<div class="w3tc-page-container">
	<div class="w3tc-card-container">
<?php

foreach ( $cards as $feature_id => $card ) {
	$card_classes  = 'w3tc-card';
	$title_classes = 'w3tc-card-title';
	$is_premium    = ! empty( $card['is_premium'] );
	$is_new        = ! empty( $card['is_new'] );

	if ( $is_premium ) {
		$card_classes  .= ' w3tc-card-premium';
		$title_classes .= ' w3tc-card-premium';
	}

	if ( $is_premium && ! $is_pro ) {
		$card_classes .= ' w3tc-card-upgrade';
	}

	?>
		<div class="<?php echo $card_classes; ?>" id="w3tc-feature-<?php echo esc_attr( $feature_id ); ?>">
	<?php

	if ( $is_new ) {
		?>
			<div class="w3tc-card-ribbon-new"><span>NEW</span></div>
		<?php
	}

	?>
			<div class="<?php echo $title_classes; ?>">
				<p><?php echo $card['title']; ?></p>
	<?php
	if ( $is_premium ) {
		?>
				<p class="w3tc-card-pro"><?php echo __( 'PRO FEATURE', 'w3-total-cache' ); ?></p>
		<?php
	}
	?>
			</div>
			<div class="w3tc-card-icon"><span class="dashicons <?php echo $card['icon']; ?>"></span></div>
			<div class="w3tc-card-body"><p><?php echo $card['text']; ?></p></div>
			<div class="w3tc-card-footer">
				<div class="w3tc-card-button">
	<?php

	if ( $is_premium && ! $is_pro ) {
		?>
					<button class="button w3tc-gopro-button button-buy-plugin" data-src="feature_showcase">Unlock Feature</button>
		<?php
	} elseif ( ! empty( $card['button'] ) ) {
		echo $card['button'];
	}

	?>
				</div><div class="w3tc-card-links"><?php echo $card['link']; ?></div>
			</div>
		</div>
	<?php
}

?>
	</div>
</div>
