<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

$state_master = Dispatcher::config_state_master();

?>
<div id="w3tc-support-us">
	<div class="w3tc-overlay-logo"></div>
	<header>
		<div class="left" style="float:left">
			<h2>Frederick Townes</h2>
			<h3>CEO, W3 EDGE</h3>
		</div>
		<div class="right" style="float:right">
			<div style="display: inline-block">
				<iframe height="21" width="100" src="//www.facebook.com/plugins/like.php?href=https%3A%2F%2Fwww.facebook.com%2FW3EDGE&amp;width=100&amp;height=21&amp;colorscheme=light&amp;layout=button_count&amp;action=like&amp;show_faces=true&amp;send=false&amp;appId=53494339074" scrolling="no" frameborder="0" style="border:none; overflow:hidden; width:100px; height:21px;" allowTransparency="true"></iframe>
			</div>
			<div style="display: inline-block; margin-left: 10px;">
				<a href="https://twitter.com/w3edge" class="twitter-follow-button" data-show-count="true" data-show-screen-name="false" target="_blank">Follow @w3edge</a>
				<script>!function(d,s,id){var js,fjs=d.getElementsByTagName(s)[0],p=/^http:/.test(d.location)?'http':'https';if(!d.getElementById(id)){js=d.createElement(s);js.id=id;js.src=p+'://platform.twitter.com/widgets.js';fjs.parentNode.insertBefore(js,fjs);}}(document, 'script', 'twitter-wjs');</script>
			</div>
			<div style="display: inline-block; margin-left: 10px;">
				<!-- Place this tag where you want the widget to render. -->
				<div class="g-follow" data-annotation="bubble" data-height="20" data-href="https://plus.google.com/106009620651385224281" data-rel="author"></div>
				<!-- Place this tag after the last widget tag. -->
				<script type="text/javascript">
					(function() {
						var po = document.createElement('script'); po.type = 'text/javascript'; po.async = true;
						po.src = 'https://apis.google.com/js/plusone.js';
						var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(po, s);
					})();
				</script>
			</div>
		</div>
	</header>
	<form action="<?php echo esc_attr( Util_Ui::admin_url( 'admin.php?page=w3tc_general' ) ); ?>&amp;w3tc_config_save_support_us" method="post">

	<div class="content">
			<h3 class="font-palette-dark-skies"><?php esc_html_e( 'Thank you! You\'ve been using W3 Total Cache for seven days or so! Please support us:', 'w3-total-cache' ); ?></h3>

			<ul>
				<li>
					<label>
						Please give us a five star rating:<br>
						<?php
						echo wp_kses(
							Util_Ui::action_button(
								__( 'Login & Rate Us', 'w3-total-cache' ),
								W3TC_SUPPORT_US_RATE_URL,
								'btn w3tc-size image btn-default palette-wordpress',
								true
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
					</label>
				</li>
				<li>
					<label>Post a tweet:<br />
						<?php
						$tweet_url = 'http://twitter.com/home/?status=' . rawurlencode( W3TC_SUPPORT_US_TWEET );
						echo wp_kses(
							Util_Ui::action_button(
								__( 'Tell Your Friends', 'w3-total-cache' ),
								$tweet_url,
								'btn w3tc-size image btn-default palette-twitter',
								true
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
						echo wp_kses(
							Util_Ui::hidden(
								__( 'tweeted' ),
								__( 'tweeted' ),
								'0'
							),
							array(
								'input' => array(
									'type'  => array(),
									'id'    => array(),
									'name'  => array(),
									'value' => array(),
								),
							)
						);
						?>
					</label>
				</li>
			</ul>
			<p>
				<label class="w3tc_signup_email" for="email">Don't forget to join our newsletter:<br />
					<input id="email" name="email" type="text" class="form-control w3tc-size" value="<?php echo esc_attr( $email ); ?>">
				</label><br />
				<input type="checkbox" name="signmeup" id="signmeup" class="css-checkbox" value="1" checked="checked" />
				<label for="signmeup" class="css-label"> <?php esc_html_e( 'Yes, sign me up.', 'w3-total-cache' ); ?> </label>
			</p>
			<?php if ( $state_master->get_string( 'license.community_terms' ) !== 'accept' ) : ?>
				<p>
					<input type="checkbox" name="accept_terms" id="accept_terms" class="css-checkbox" value="1"/>
					<label for="accept_terms" class="css-label">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML a tag to W3TC Terms page, 2 closing HTML a tag.
								__(
									'Please review the latest %1$sterms of use and privacy policy%2$s, and accept them.',
									'w3-total-cache'
								),
								'<a href="' . esc_url( W3TC_TERMS_URL ) . '" target="blank">',
								'</a>'
							),
							array(
								'a' => array(
									'href'   => array(),
									'target' => array(),
								),
							)
						);
						?>
					</label>
				</p>
			<?php endif ?>
	</div>
	<div class="w3tc_overlay_footer">
		<p>
			<?php wp_nonce_field( 'w3tc' ); ?>
			<input type="submit" class="btn w3tc-size image w3tc-button-save btn-primary outset save palette-turquoise " value="Save &amp; close">
			<input type="button" class="btn w3tc-size btn-default outset palette-light-grey w3tc_lightbox_close" value="Cancel">
		</p>
	</div>
	</form>
</div>
