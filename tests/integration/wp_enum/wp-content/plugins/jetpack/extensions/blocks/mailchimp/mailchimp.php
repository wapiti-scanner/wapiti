<?php
/**
 * Mailchimp Block.
 *
 * @since 7.1.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Mailchimp;

use Automattic\Jetpack\Blocks;
use Jetpack;
use Jetpack_Gutenberg;
use Jetpack_Options;

const FEATURE_NAME = 'mailchimp';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	if (
		( defined( 'IS_WPCOM' ) && IS_WPCOM )
		|| Jetpack::is_connection_ready()
	) {
		Blocks::jetpack_register_block(
			BLOCK_NAME,
			array(
				'render_callback' => __NAMESPACE__ . '\load_assets',
				'supports'        => array(
					'align'   => array( 'wide', 'full' ),
					'color'   => array(
						'gradients' => true,
					),
					'spacing' => array(
						'padding' => true,
						'margin'  => true,
					),
				),
			)
		);
	}
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Mailchimp block registration/dependency declaration.
 *
 * @param array  $attr - Array containing the Mailchimp block attributes.
 * @param string $content - Mailchimp block content.
 *
 * @return string
 */
function load_assets( $attr, $content ) {

	if ( ! verify_connection() ) {
		return null;
	}

	$values  = get_attributes_with_defaults( $attr );
	$blog_id = ( defined( 'IS_WPCOM' ) && IS_WPCOM )
		? get_current_blog_id()
		: Jetpack_Options::get_option( 'id' );
	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );
	$wrapper_attributes = \WP_Block_Supports::get_instance()->apply_block_supports();
	$classes            = ! empty( $wrapper_attributes['class'] ) ? $wrapper_attributes['class'] : '';
	$amp_form_action    = sprintf( 'https://public-api.wordpress.com/rest/v1.1/sites/%s/email_follow/amp/subscribe/', $blog_id );
	$is_amp_request     = Blocks::is_amp_request();

	ob_start();
	?>

	<div class="<?php echo esc_attr( $classes ); ?>"<?php echo ! empty( $wrapper_attributes['style'] ) ? ' style="' . esc_attr( $wrapper_attributes['style'] ) . '"' : ''; ?> data-blog-id="<?php echo esc_attr( $blog_id ); ?>">
		<form
			aria-describedby="wp-block-jetpack-mailchimp_consent-text"
			<?php if ( $is_amp_request ) : ?>
				action-xhr="<?php echo esc_url( $amp_form_action ); ?>"
				method="post"
				id="mailchimp_form"
				target="_top"
				on="submit-success:AMP.setState( { mailing_list_status: 'subscribed', mailing_list_email: event.response.email } )"
			<?php endif; ?>
		>
			<p>
				<input
					aria-label="<?php echo esc_attr( $values['emailPlaceholder'] ); ?>"
					placeholder="<?php echo esc_attr( $values['emailPlaceholder'] ); ?>"
					required
					title="<?php echo esc_attr( $values['emailPlaceholder'] ); ?>"
					type="email"
					name="email"
				/>
			</p>
			<?php foreach ( is_array( $values['interests'] ) ? $values['interests'] : array() as $interest ) : ?>
				<input
					name="interests[<?php echo esc_attr( $interest ); ?>]"
					type="hidden"
					class="mc-submit-param"
					value="1"
				/>
			<?php endforeach; ?>
			<?php
			if (
				! empty( $values['signupFieldTag'] )
				&& ! empty( $values['signupFieldValue'] )
				) :
				?>
				<input
					name="merge_fields[<?php echo esc_attr( $values['signupFieldTag'] ); ?>]"
					type="hidden"
					class="mc-submit-param"
					value="<?php echo esc_attr( $values['signupFieldValue'] ); ?>"
				/>
			<?php endif; ?>
			<?php echo render_button( $attr, $content ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<p id="wp-block-jetpack-mailchimp_consent-text">
				<?php echo wp_kses_post( $values['consentText'] ); ?>
			</p>

			<?php if ( $is_amp_request ) : ?>

				<div submit-success>
					<template type="amp-mustache">
						<div class="wp-block-jetpack-mailchimp_notification wp-block-jetpack-mailchimp_success wp-block-jetpack-mailchimp__is-amp">
							<?php echo esc_html( $values['successLabel'] ); ?>
						</div>
					</template>
				</div>
				<div submit-error>
					<template type="amp-mustache">
						<div class="wp-block-jetpack-mailchimp_notification wp-block-jetpack-mailchimp_error wp-block-jetpack-mailchimp__is-amp">
							<?php echo esc_html( $values['errorLabel'] ); ?>
						</div>
					</template>
				</div>
				<div submitting>
					<template type="amp-mustache">
						<div class="wp-block-jetpack-mailchimp_notification wp-block-jetpack-mailchimp_processing wp-block-jetpack-mailchimp__is-amp" role="status">
							<?php echo esc_html( $values['processingLabel'] ); ?>
						</div>
					</template>
				</div>

			<?php endif; ?>

		</form>
		<?php if ( ! $is_amp_request ) : ?>

			<div class="wp-block-jetpack-mailchimp_notification wp-block-jetpack-mailchimp_processing" role="status">
				<?php echo esc_html( $values['processingLabel'] ); ?>
			</div>
			<div class="wp-block-jetpack-mailchimp_notification wp-block-jetpack-mailchimp_success" role="status">
				<?php echo esc_html( $values['successLabel'] ); ?>
			</div>
			<div class="wp-block-jetpack-mailchimp_notification wp-block-jetpack-mailchimp_error" role="alert">
				<?php echo esc_html( $values['errorLabel'] ); ?>
			</div>

		<?php endif; ?>
	</div>
	<?php
	$html = ob_get_clean();
	return $html;
}

/**
 * Mailchimp connection/list selection verification.
 *
 * @return boolean
 */
function verify_connection() {
	$option = get_option( 'jetpack_mailchimp' );
	if ( ! $option ) {
		return false;
	}
	$data = json_decode( $option, true );
	if ( ! $data ) {
		return false;
	}
	return isset( $data['follower_list_id'], $data['keyring_id'] );
}

/**
 * Builds complete set of attributes using default values where needed.
 *
 * @param array $attr Saved set of attributes for the Mailchimp block.
 * @return array
 */
function get_attributes_with_defaults( $attr ) {
	$values   = array();
	$defaults = array(
		'emailPlaceholder' => esc_html__( 'Enter your email', 'jetpack' ),
		'consentText'      => esc_html__( 'By clicking submit, you agree to share your email address with the site owner and Mailchimp to receive marketing, updates, and other emails from the site owner. Use the unsubscribe link in those emails to opt out at any time.', 'jetpack' ),
		'processingLabel'  => esc_html__( 'Processing…', 'jetpack' ),
		'successLabel'     => esc_html__( 'Success! You\'re on the list.', 'jetpack' ),
		'errorLabel'       => esc_html__( 'Whoops! There was an error and we couldn\'t process your subscription. Please reload the page and try again.', 'jetpack' ),
		'interests'        => array(),
		'signupFieldTag'   => '',
		'signupFieldValue' => '',
	);

	foreach ( $defaults as $id => $default ) {
		$values[ $id ] = isset( $attr[ $id ] ) ? $attr[ $id ] : $default;
	}

	return $values;
}

/**
 * Renders the Mailchimp block button using inner block content if available
 * otherwise generating the HTML button from deprecated attributes.
 *
 * @param array  $attr Attributes for the Mailchimp block.
 * @param string $content Mailchimp block content.
 *
 * @return string
 */
function render_button( $attr, $content ) {
	if ( ! empty( $content ) ) {
		$block_id = wp_unique_id( 'mailchimp-button-block-' );
		return str_replace( 'mailchimp-widget-id', $block_id, $content );
	}

	return render_deprecated_button( $attr );
}

/**
 * Renders HTML button from deprecated Mailchimp block attributes.
 *
 * @param array $attr Mailchimp block attributes.
 * @return string
 */
function render_deprecated_button( $attr ) {
	$default       = esc_html__( 'Join my email list', 'jetpack' );
	$text          = empty( $attr['submitButtonText'] ) ? $default : $attr['submitButtonText'];
	$button_styles = array();

	if ( ! empty( $attr['customBackgroundButtonColor'] ) ) {
		array_push(
			$button_styles,
			sprintf(
				'background-color: %s',
				sanitize_hex_color( $attr['customBackgroundButtonColor'] )
			)
		);
	}

	if ( ! empty( $attr['customTextButtonColor'] ) ) {
		array_push(
			$button_styles,
			sprintf(
				'color: %s',
				sanitize_hex_color( $attr['customTextButtonColor'] )
			)
		);
	}

	$button_styles  = implode( ';', $button_styles );
	$button_classes = 'components-button is-button is-primary ';

	if ( ! empty( $attr['submitButtonClasses'] ) ) {
		$button_classes .= $attr['submitButtonClasses'];
	}

	return sprintf(
		'<p><button type="submit" class="%s" style="%s">%s</button></p>',
		esc_attr( $button_classes ),
		esc_attr( $button_styles ),
		wp_kses_post( $text )
	);
}
