<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<div class="w3tc-overlay-logo"></div>
<header>
</header>
<div class="w3tchelp_content">
	<h3><?php esc_html_e( 'Hang on!', 'w3-total-cache' ); ?></h3>
	<p>
		<?php esc_html_e( 'In the best case, the usage of minify optimization is a trial and error process, it\'s', 'w3-total-cache' ); ?>
		<em><?php esc_html_e( ' not ', 'w3-total-cache' ); ?></em>
		<?php esc_html_e( 'an "instant on" or "set it and forget it" optimization technique.', 'w3-total-cache' ); ?>
	</p>
	<p>
		<?php
		esc_html_e(
			'There are lots of reasons why minify cannot work for all sites under all circumstances and they
				have nothing to do with W3 Total Cache: Your site\'s content, your server(s), your plugins and
				your theme are all unique, that means that minify cannot automatically work for everyone.',
			'w3-total-cache'
		);
		?>
	</p>

	<h3><?php esc_html_e( 'What is minification exactly?', 'w3-total-cache' ); ?></h3>
	<ul class="w3tchelp_content_list">
		<li>
			<?php
			esc_html_e(
				'Minification is a process of reducing the file size to improve user experience and it requires
					testing in order to get it right &mdash; as such it doesn\'t work for everyone.',
				'w3-total-cache'
			);
			?>
		</li>
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'The interactions and dependencies of %1$sCSS%2$s or %3$sJS%4$s on each other can be complex.
							Themes and plugins are typically created by various developers and can be combined in
							millions of combinations. As a result, W3 Total Cache cannot take all of those nuances into
							account, it just does the operation and let\'s you tune to what degree it does it, it
							doesn\'t "validate" the result or know if it\'s good or bad; a human must do that.',
						'w3-total-cache'
					),
					'<acronym title="' . esc_html__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_html__( 'JavaScript', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			);
			?>
		</li>
	</ul>

	<h3><?php esc_html_e( 'Still want to get started? Now for the Pro\' tips:', 'w3-total-cache' ); ?></h3>
	<ol class="w3tchelp_content_list">
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Start with minify for your %1$sCSS%2$s using auto mode first. If you have any issues at that step,
							contact your developer(s) and report a bug. They should be able to point you in the right
							direction or correct the issue in a future update.',
						'w3-total-cache'
					),
					'<acronym title="' . esc_html__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			);
			?>
		</li>
		<li>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
					// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag.
					__(
						'Once %1$sCSS%2$s is optimized, try %3$sJS%4$s minification. If auto mode doesn\'t work for
							you, be sure to check the web browsers error console to quickly confirm that the optimization
							isn\'t working. If the JavaScript is working, you can either make additional optimizations for
							user experience like experimenting with embed locations etc or further reducing file size etc.
							However, if you\'re having errors try the "combine only" option and if that still generates
							errors, there are bugs in the code of your theme or plugins or both that prevent minification
							of %5$sJS%6$s from working automatically.',
						'w3-total-cache'
					),
					'<acronym title="' . esc_html__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_html__( 'JavaScript', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_html__( 'JavaScript', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			);
			?>
		</li>
	</ol>

	<div>
		<input type="submit" class="btn w3tc-size image btn-primary outset save palette-turquoise "
			value="<?php esc_attr_e( 'I Understand the Risks', 'w3-total-cache' ); ?>">
		<?php
		echo wp_kses(
			Util_Ui::button_link(
				'Do It For Me',
				'admin.php?page=w3tc_support',
				false,
				'btn w3tc-size image btn-primary outset save palette-turquoise w3tc-button-ignore-change'
			),
			array(
				'input' => array(
					'type'    => array(),
					'name'    => array(),
					'class'   => array(),
					'value'   => array(),
					'onclick' => array(),
				),
			)
		);
		?>
	</div>
</div>
