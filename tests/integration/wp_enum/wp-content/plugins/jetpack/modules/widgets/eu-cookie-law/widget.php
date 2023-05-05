<?php // phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
/**
 * Widget for Cookies and Consent.
 *
 * @package automattic/jetpack
 */
?>

<div
	class="<?php echo esc_attr( implode( ' ', $classes ) ); ?>"
	data-hide-timeout="<?php echo (int) $instance['hide-timeout']; ?>"
	data-consent-expiration="<?php echo (int) $instance['consent-expiration']; ?>"
	id="eu-cookie-law"
>
	<form method="post">
		<input type="submit" value="<?php echo esc_attr( $instance['button'] ); ?>" class="accept" />
	</form>

	<?php
	if ( 'default' === $instance['text'] || empty( $instance['customtext'] ) ) {
		echo nl2br( esc_html( $instance['default-text'] ) );
	} else {
		echo nl2br( esc_html( $instance['customtext'] ) );
	}
	?>

	<?php
	$is_default_policy = 'default' === $instance['policy-url'] || empty( $instance['custom-policy-url'] );
	$policy_link_url   = $is_default_policy ? $instance['default-policy-url'] : $instance['custom-policy-url'];
	$policy_link_rel   = $is_default_policy ? 'nofollow' : '';
	?>
	<a href="<?php echo esc_url( $policy_link_url ); ?>" rel="<?php echo esc_attr( $policy_link_rel ); ?>">
		<?php echo esc_html( $instance['policy-link-text'] ); ?>
	</a>
</div>
