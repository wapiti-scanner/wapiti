<?php
/**
 * Constant Contact page template.
 *
 * @var string $sign_up_link           Sign up link.
 * @var string $wpbeginners_guide_link Link to a WPBeginners blog post.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<div class="wrap wpforms-admin-wrap wpforms-constant-contact-wrap">
	<h1 class="page-title"><?php esc_html_e( 'Constant Contact', 'wpforms-lite' ); ?></h1>
	<div class="wpforms-admin-content">
		<h2><?php esc_html_e( 'Grow Your Website with WPForms + Email Marketing', 'wpforms-lite' ); ?></h2>
		<p><?php esc_html_e( 'Wondering if email marketing is really worth your time?', 'wpforms-lite' ); ?></p>
		<p>
			<?php
			echo wp_kses(
				__( 'Email is hands-down the most effective way to nurture leads and turn them into customers, with a return on investment (ROI) of <strong>$44 back for every $1 spent</strong> according to DMA.', 'wpforms-lite' ),
				[ 'strong' => [] ]
			);
			?>
		</p>
		<p><?php esc_html_e( 'Here are 3 big reasons why every smart business in the world has an email list:', 'wpforms-lite' ); ?></p>
		<a href="<?php echo esc_url( $sign_up_link ); ?>" target="_blank" rel="noopener noreferrer" class="logo-link">
			<?php
			printf(
				'<img src="%s" srcset="%s 2x" alt="" class="logo">',
				esc_url( WPFORMS_PLUGIN_URL . 'assets/images/constant-contact/cc-about-logo.png' ),
				esc_url( WPFORMS_PLUGIN_URL . 'assets/images/constant-contact/cc-about-logo@2x.png' )
			);
			?>
		</a>
		<ol class="reasons">
			<li>
				<?php
				echo wp_kses(
					__( '<strong>Email is still #1</strong> - At least 91% of consumers check their email on a daily basis. You get direct access to your subscribers, without having to play by social media\'s rules and algorithms.', 'wpforms-lite' ),
					[ 'strong' => [] ]
				);
				?>
			</li>
			<li>
				<?php
				echo wp_kses(
					__( '<strong>You own your email list</strong> - Unlike with social media, your list is your property and no one can revoke your access to it.', 'wpforms-lite' ),
					[ 'strong' => [] ]
				);
				?>
			</li>
			<li>
				<?php
				echo wp_kses(
					__( '<strong>Email converts</strong> - People who buy products marketed through email spend 138% more than those who don\'t receive email offers.', 'wpforms-lite' ),
					[ 'strong' => [] ]
				);
				?>
			</li>
		</ol>
		<p><?php esc_html_e( 'That\'s why it\'s crucial to start collecting email addresses and building your list as soon as possible.', 'wpforms-lite' ); ?></p>
		<p>
			<?php
			echo sprintf(
				wp_kses( /* translators: %s - WPBeginners.com Guide to Email Lists URL. */
					__( 'For more details, see this guide on <a href="%s" target="_blank" rel="noopener noreferrer">why building your email list is so important</a>.', 'wpforms-lite' ),
					[
						'a' => [
							'href'   => [],
							'target' => [],
							'rel'    => [],
						],
					]
				),
				esc_url( $wpbeginners_guide_link )
			);
			?>
		</p>
		<hr/>
		<h2><?php esc_html_e( 'You\'ve Already Started - Here\'s the Next Step (It\'s Easy)', 'wpforms-lite' ); ?></h2>
		<p><?php esc_html_e( 'Here are the 3 things you need to build an email list:', 'wpforms-lite' ); ?></p>
		<ol>
			<li><?php esc_html_e( 'A Website or Blog', 'wpforms-lite' ); ?> <span class="dashicons dashicons-yes"></span></li>
			<li><?php esc_html_e( 'High-Converting Form Builder', 'wpforms-lite' ); ?> <span class="dashicons dashicons-yes"></span></li>
			<li class="bold-marker"><strong><?php esc_html_e( 'The Best Email Marketing Service', 'wpforms-lite' ); ?></strong></li>
		</ol>
		<p><?php esc_html_e( 'With a powerful email marketing service like Constant Contact, you can instantly send out mass notifications and beautifully designed newsletters to engage your subscribers.', 'wpforms-lite' ); ?></p>
		<p>
			<a href="<?php echo esc_url( $sign_up_link ); ?>" class="button" target="_blank" rel="noopener noreferrer">
				<?php esc_html_e( 'Get Started with Constant Contact for Free', 'wpforms-lite' ); ?>
			</a>
		</p>
		<p><?php esc_html_e( 'WPForms plugin makes it fast and easy to capture all kinds of visitor information right from your WordPress site - even if you don\'t have a Constant Contact account.', 'wpforms-lite' ); ?></p>
		<p><?php esc_html_e( 'But when you combine WPForms with Constant Contact, you can nurture your contacts and engage with them even after they leave your website. When you use Constant Contact + WPForms together, you can:', 'wpforms-lite' ); ?></p>
		<ul>
			<li><?php esc_html_e( 'Seamlessly add new contacts to your email list', 'wpforms-lite' ); ?></li>
			<li><?php esc_html_e( 'Create and send professional email newsletters', 'wpforms-lite' ); ?></li>
			<li><?php esc_html_e( 'Get expert marketing and support', 'wpforms-lite' ); ?></li>
		</ul>
		<p>
			<a href="<?php echo esc_url( $sign_up_link ); ?>" target="_blank" rel="noopener noreferrer">
				<strong><?php esc_html_e( 'Try Constant Contact Today', 'wpforms-lite' ); ?></strong>
			</a>
		</p>
		<hr/>
		<h2><?php esc_html_e( 'WPForms Makes List Building Easy', 'wpforms-lite' ); ?></h2>
		<p><?php esc_html_e( 'When creating WPForms, our goal was to make a WordPress forms plugin that\'s both EASY and POWERFUL.', 'wpforms-lite' ); ?></p>
		<p><?php esc_html_e( 'We made the form creation process extremely intuitive, so you can create a form to start capturing emails within 5 minutes or less.', 'wpforms-lite' ); ?></p>
		<p><?php esc_html_e( 'Here\'s how it works.', 'wpforms-lite' ); ?></p>
		<div class="steps">
			<?php
			foreach (
				[
					esc_html__( 'Select from our pre-built templates, or create a form from scratch.', 'wpforms-lite' ),
					esc_html__( 'Drag and drop any field you want onto your signup form.', 'wpforms-lite' ),
					esc_html__( 'Connect your Constant Contact email list.', 'wpforms-lite' ),
					esc_html__( 'Add your new form to any post, page, or sidebar.', 'wpforms-lite' ),
				] as $index => $item
			) {
				++ $index;
				?>
				<figure class="step">
					<?php
					printf(
						'<div class="step-image-wrapper"><img src="%1$s" alt=""><a href="%1$s" class="hover" data-lity></a></div><figcaption>%2$d. %3$s</figcaption>',
						esc_url( WPFORMS_PLUGIN_URL . 'assets/images/constant-contact/cc-about-step' . $index . '.png' ),
						absint( $index ),
						esc_html( $item )
					);
					?>
				</figure>
			<?php } ?>
		</div>
		<p><?php esc_html_e( 'It doesn\'t matter what kind of business you run, what kind of website you have, or what industry you are in - you need to start building your email list today.', 'wpforms-lite' ); ?></p>
		<p><strong><?php esc_html_e( 'With Constant Contact + WPForms, growing your list is easy.', 'wpforms-lite' ); ?></strong></p>
	</div>
</div>
