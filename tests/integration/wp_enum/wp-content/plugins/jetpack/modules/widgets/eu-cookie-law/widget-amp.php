<?php // phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
/**
 * AMP Widget for Cookies and Consent.
 *
 * @package automattic/jetpack
 */
?>

<amp-consent id="eu-cookie-consent" layout="nodisplay" class="widget widget_eu_cookie_law_widget<?php echo esc_attr( ! empty( $instance['position'] ) && 'top' === $instance['position'] ? ' top' : '' ); ?>">
	<script type="application/json">
		{
			"consentInstanceId": "eu-cookie-consent",
			"consentRequired": true,
			"promptUI": "eu-cookie-consent-prompt"
		}
	</script>
	<div class="popupOverlay" id="eu-cookie-consent-prompt">
		<div class="consentPopup<?php echo esc_attr( ! empty( $instance['color-scheme'] ) && 'negative' === $instance['color-scheme'] ? ' negative' : '' ); ?>" id="eu-cookie-law">
			<form>
				<input type="button" on="tap:eu-cookie-consent.accept" class="accept" value="<?php echo esc_attr( $instance['button'] ); ?>" />
			</form>
			<?php
			if ( 'default' === $instance['text'] || empty( $instance['customtext'] ) ) {
				echo wp_kses_post( nl2br( $instance['default-text'] ) );
			} else {
				echo esc_html( $instance['customtext'] );
			}

			$is_default_policy = 'default' === $instance['policy-url'] || empty( $instance['custom-policy-url'] );
			$policy_link_url   = $is_default_policy ? $instance['default-policy-url'] : $instance['custom-policy-url'];
			$policy_link_rel   = $is_default_policy ? 'nofollow' : '';
			?>
			<a href="<?php echo esc_url( $policy_link_url ); ?>" rel="<?php echo esc_attr( $policy_link_rel ); ?>">
				<?php echo esc_html( $instance['policy-link-text'] ); ?>
			</a>
		</div>
	</div>
</amp-consent>
